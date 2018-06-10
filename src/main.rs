#![feature(
    proc_macro,
    catch_expr,
    type_ascription,
)]

use std::{
    net, process,

    str::FromStr,
    sync::{
        Arc,
        Mutex,
    },
    collections::{
        hash_map,
        HashMap,
    },
};

use failure::{
    Error,
    ResultExt,
    bail,
};

use hyper::{
    rt::Future,
};

use structopt::StructOpt;

extern crate hyper;
extern crate failure;
extern crate structopt;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate sha2;
extern crate bytes;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long = "bind-address", default_value = "127.0.0.1:8000")]
    bind_address: net::SocketAddr,
}

fn parse_path(mut path: &str) -> Result<(&str, &str, &str), Error> {
    if !path.starts_with("/v2/") {
        bail!("only /v2/ paths allowed");
    }
    path = &path[4..];
    if path.len() == 0 {
        bail!("empty path");
    }
    if &path[path.len() - 1..] == "/" {
        path = &path[..path.len()-1];
    }
    let (path, label) = match path.rfind('/') {
        Some(n) => (&path[..n], &path[n+1..]),
        _ => bail!("missing label"),
    };
    let (path, op) = match path.rfind('/') {
        Some(n) => (&path[..n], &path[n+1..]),
        _ => bail!("missing op"),
    };

    Ok((path, label, op))
}

mod docker {
    use std::{
        fmt, str::FromStr,
    };

    use serde::{
        self,
        de::{
            Deserialize,
            Deserializer,
            Visitor,
        },
        ser::{
            Serialize,
            Serializer,
        },
    };

    use serde_derive::Serialize;

    #[derive(Debug, Serialize, /*Deserialize*/)]
    pub struct ImageManifest {
        #[serde(rename = "schemaVersion")]
        pub schema_version: i32,
        #[serde(rename = "mediaType")]
        pub media_type: MediaTypeManifest,
        pub config: Ref<MediaTypeImage>,
        pub layers: Vec<Ref<MediaTypeLayer>>,
    }

    #[derive(Debug, Serialize, /*Deserialize*/)]
    pub struct ImageConfig {
        #[serde(rename = "rootfs")]
        pub root_fs: RootFs,
    }

    #[derive(Debug, Serialize, /*Deserialize*/)]
    pub struct RootFs {
        #[serde(rename = "type")]
        pub type_: &'static str,
        pub diff_ids: Vec<Digest>,
    }

    #[derive(Debug, Serialize, /*Deserialize*/)]
    pub struct Ref<T> {
        #[serde(rename = "mediaType")]
        pub media_type: T,
        pub size: usize,
        pub digest: Digest,
    }

    #[derive(Debug, PartialEq, PartialOrd, Eq, Ord)]
    pub struct Digest(pub [u8; 32]);

    impl fmt::Display for Digest {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "sha256:")?;
            for b in &self.0[..] {
                write!(f, "{:02x}", b)?;
            }
            Ok(())
        }
    }

    impl Serialize for Digest {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
                where S: Serializer {
            s.collect_str(self)
        }
    }

    impl<'de> Deserialize<'de> for Digest {
        fn deserialize<D>(d: D) -> Result<Self, D::Error>
                where D: Deserializer<'de> {

            d.deserialize_str(DigestVisitor)
        }
    }

    impl FromStr for Digest {
        type Err = ();
        fn from_str(s: &str) -> Result<Digest, ()> {
            if !s.starts_with("sha256:") { Err(())?  }
            let mut s = &s[7..];
            if s.len() != 64 { Err(())? }
            let mut digest = [0; 32];
            for b in &mut digest[..] {
                *b = u8::from_str_radix(&s[..2], 16)
                    .map_err(|_| ())?;
                s = &s[2..];
            }

            Ok(Digest(digest))
        }
    }

    struct DigestVisitor;

    impl<'de> Visitor<'de> for DigestVisitor {
        type Value = Digest;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a string starting with \"sha256:\", followed by 64 hex digits")
        }

        fn visit_str<E>(self, s: &str) -> Result<Digest, E>
                where E: serde::de::Error {
            Digest::from_str(s).map_err(|_: ()| E::invalid_value(
                serde::de::Unexpected::Str(s),
                &self))
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub struct MediaTypeManifest;
    impl serde::Serialize for MediaTypeManifest {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
                where S: serde::Serializer {
            s.serialize_str((*self).into())
        }
    }
    impl Into<&'static str> for MediaTypeManifest {
        fn into(self) -> &'static str {
            "application/vnd.docker.distribution.manifest.v2+json"
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub struct MediaTypeImage;
    impl serde::Serialize for MediaTypeImage {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
                where S: serde::Serializer {
            s.serialize_str((*self).into())
        }
    }
    impl Into<&'static str> for MediaTypeImage {
        fn into(self) -> &'static str {
            "application/vnd.docker.container.image.v1+json"
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub struct MediaTypeLayer;
    impl serde::Serialize for MediaTypeLayer {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
                where S: serde::Serializer {
            s.serialize_str((*self).into())
        }
    }
    impl Into<&'static str> for MediaTypeLayer {
        fn into(self) -> &'static str {
            "application/vnd.docker.image.rootfs.diff.tar.gzip"
        }
    }
}

fn get_store_closure(path: &str) -> Result<Vec<String>, Error> {
    eprintln!("determining closure for {}", path);
    let output = process::Command::new("nix").args(&["path-info", "--recursive", &path])
        .output()?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        bail!("\"nix path-info --recursive {}\" failed: {}", path, err);
    }
    let out = String::from_utf8(output.stdout)?;
    eprintln!("  {:?}", out);
    Ok(out.split_whitespace().map(|s| s.into()).collect())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.input(bytes);
    let mut hash = [0; 32];
    hash.copy_from_slice(&hasher.result()[..]);
    return hash;
}

fn make_config(layers: &HashMap<[u8; 32], Arc<Blob>>) -> Result<Blob, Error> {
    let cfg = docker::ImageConfig{
        root_fs: docker::RootFs {
            type_: "layers",
            diff_ids: layers.keys().map(|k| docker::Digest(*k)).collect(),
        },
    };

    let bytes = serde_json::to_vec(&cfg)?;
    let hash = sha256(&bytes);

    Ok(Blob { hash, bytes })
}

fn make_manifest(cfg: &Blob, layers: &HashMap<[u8; 32], Arc<Blob>>) -> Result<Blob, Error> {
    let m = docker::ImageManifest {
        schema_version: 2,
        media_type: docker::MediaTypeManifest,
        config: docker::Ref{
            media_type: docker::MediaTypeImage,
            size: cfg.bytes.len(),
            digest: docker::Digest(cfg.hash),
        },
        layers: layers.iter().map(|(_, blob)|
            docker::Ref{
                media_type: docker::MediaTypeLayer,
                size: blob.bytes.len(),
                digest: docker::Digest(blob.hash),
            }).collect(),
    };

    let bytes = serde_json::to_vec(&m)?;
    let hash = sha256(&bytes);

    Ok(Blob { hash, bytes })
}

fn tar(path: &str) -> Result<([u8; 32], Vec<u8>), Error> {
    eprintln!("tar c {} -P", path);
    let output = process::Command::new("tar").args(&["c", path, "-P"])
        .output()?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        bail!("\"tar c {} -P\" failed: {}", path, err);
    }

    let hash = sha256(&output.stdout);
    eprintln!("  {:?}, {} bytes", hash, output.stdout.len());
    Ok((hash, output.stdout))
}

fn slurp_store_path(state: &Mutex<State>, name: &str)
        -> Result<Arc<Image>, Error> {
    let mut state = state.lock().unwrap();
    let state: &mut State = &mut state;
    let path = format!("/nix/store/{}", name);
    let vacant_image = match state.image_for_path.entry(path.clone()) {
        hash_map::Entry::Occupied(e) => return Ok(e.get().clone()),
        hash_map::Entry::Vacant(e) => e,
    };

    let closure = match state.closure_for_path.entry(path.clone()) {
        hash_map::Entry::Occupied(e) => e.into_mut(),
        hash_map::Entry::Vacant(e) => e.insert(get_store_closure(&path)
            .context("determining closure")?),
    };

    let mut layers = HashMap::new();
    for path in closure {
        let layer = match state.store_path_blobs.entry(path.clone()) {
            hash_map::Entry::Occupied(e) => e.into_mut(),
            hash_map::Entry::Vacant(e) => {
                let (hash, bytes) = tar(&path).context("creating tarball")?;
                let layer = Arc::new(Blob {
                    hash: hash,
                    bytes: bytes
                });
                e.insert(layer)
            }
        };

        layers.insert(layer.hash, layer.clone());
    }

    let cfg = Arc::new(make_config(&layers)?);
    let manifest = Arc::new(make_manifest(&cfg, &layers)?);
    let image = Arc::new(Image { cfg, manifest, layers });

    vacant_image.insert(image.clone());

    Ok(image)
}

struct Blob {
    hash: [u8; 32],
    bytes: Vec<u8>,
}

struct Image {
    cfg: Arc<Blob>,
    manifest: Arc<Blob>,
    layers: HashMap<[u8; 32], Arc<Blob>>,
}

struct State {
    image_for_path: HashMap<String, Arc<Image>>,
    closure_for_path: HashMap<String, Vec<String>>,
    store_path_blobs: HashMap<String, Arc<Blob>>,
}

fn resp(blob: &Blob, content_type: &'static str)
        -> Result<hyper::Response<hyper::Body>, Error> {
    return Ok(hyper::Response::builder()
        .header("Docker-Content-Digest",
            docker::Digest(blob.hash).to_string().into(): bytes::Bytes)
        .header(hyper::header::CONTENT_LENGTH,
            &blob.bytes.len().to_string()[..])
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(hyper::Body::from(blob.bytes.clone()))?)
}

fn handle_request(state: &Mutex<State>,
            req: hyper::Request<hyper::Body>)
        -> Result<hyper::Response<hyper::Body>, Error> {
    let path = req.uri().path();
    eprintln!("request path: {}", path);
    if path == "/v2/" {
        return Ok(hyper::Response::builder()
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(hyper::Body::from("yeah i support v2"))?);
    }
    let (name, label, op) = parse_path(path).context("parsing request path")?;
    println!("  -> name={:?}, label={:?} op={:?}", name, label, op);

    let image = slurp_store_path(state, name)
        .context("loading store contents")?;

    if op == "manifests" {
        return resp(&image.manifest,
            docker::MediaTypeManifest.into(): &'static str);
    } else if op == "blobs" {
        let digest = docker::Digest::from_str(label)
            .map_err(|_| failure::format_err!("weird digest: {}", label))?;
        if digest.0 == image.cfg.hash {
            return resp(&image.cfg,
                docker::MediaTypeImage.into(): &'static str);
        }
        let blob = image.layers.get(&digest.0).ok_or_else(||
            failure::format_err!("don't have layer for {}", digest))?;
        return resp(blob, "application/octet-stream");
    }

    Ok(hyper::Response::builder()
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body("hi".into())?)
}

fn unwrap_or_500<B>(r: Result<hyper::Response<B>, Error>)
        -> hyper::Response<B>
        where B: From<String> {
    r.unwrap_or_else(|e| {
        eprintln!("request error: {:?}", e);
        hyper::Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body(B::from(e.to_string())).unwrap()
    })
}

fn main_() -> Result<(), Error> {
    let opt = Opt::from_args();

    let state = State {
        image_for_path: HashMap::new(),
        closure_for_path: HashMap::new(),
        store_path_blobs: HashMap::new(),
    };
    let state = Arc::new(Mutex::new(state));

    let new_service = move || {
        let state = state.clone();
        let f = move |req| unwrap_or_500(handle_request(&state, req));
        hyper::service::service_fn_ok(f)
    };

    let server = hyper::server::Server::try_bind(&opt.bind_address)?
        .serve(new_service)
        .map_err(|e| eprintln!("server error: {}", e));

    let () = hyper::rt::run(server);
    Ok(())
}


fn main() {
    main_().unwrap();
}
