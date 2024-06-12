# tnt 🧨
Tnt is a small, toy BitTorrent client written in C, using only the standard library. Tnt aims to provide a basic understanding of the protocol for those who want to learn it or implement it themselves.
Tnt runs on a small, built-in event loop on a single thread. Inspired by this awesome blog [post](https://blog.jse.li/posts/torrent/).

## Install

```sh
git clone https://github.com/sujanan/tnt.git
cd tnt
make
make install
```

## Usage
Try downloading something from [here](https://fosstorrents.com/).
```sh
tnt <torrent>
```
[![asciicast](https://asciinema.org/a/RM21Pp5RneXh93iUOHdXMiNIY.svg)](https://asciinema.org/a/RM21Pp5RneXh93iUOHdXMiNIY)

