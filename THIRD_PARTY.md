# Bundled dependencies

NEO Tunnel's MIT license applies to its original source. Release archives include the following independent programs.

- frp v0.72.0 is Apache-2.0 licensed. Its license is bundled. [Source and original releases](https://github.com/fatedier/frp/releases/tag/v0.72.0)
- HAProxy 3.4.7 is GPLv2 with files under additional compatible terms described in its license. The exact corresponding upstream source archive and license ship inside each binary bundle. Build from that archive with `make TARGET=linux-musl LDFLAGS=-static` on Alpine 3.22 with `build-base` and `linux-headers`. Its libc and compiler runtime are supplied by Alpine. [HAProxy release source](https://www.haproxy.org/download/3.4/src/)
- The NaiveProxy example requires separate upstream executables and licenses. [NaiveProxy](https://github.com/klzgrad/naiveproxy) · [Caddy forwardproxy](https://github.com/klzgrad/forwardproxy)

BackPack is a reference for installer and menu flow. [BackPack](https://github.com/AminMGMT/BackPack)
