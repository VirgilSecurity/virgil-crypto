FROM ubuntu:16.04

# gcc for cgo
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    gcc \
    libc6-dev \
    make \
    pkg-config \
    swig \
    doxygen \
    curl \
    ca-certificates \
    git \
    wget \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# install cmake
ENV CMAKE_VERSION 3.10.2
RUN  wget https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}.tar.gz \
     && tar xvfz cmake-${CMAKE_VERSION}.tar.gz \
     && cd cmake-${CMAKE_VERSION} \
     && ./bootstrap \
     && make -j4 \
     && make install \
     && cd - \
     && rm -rf ./cmake-*

# install golang
ENV GOLANG_VERSION 1.12.5
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 aea86e3c73495f205929cfebba0d63f1382c8ac59be081b6351681415f4063cf

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
    && echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf golang.tar.gz \
    && rm golang.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

# build virgil-crypto-go
ADD . virgil-crypto

RUN cd virgil-crypto \
    && cmake -H. -B_build -DCMAKE_INSTALL_PREFIX=_install -DLANG=go -DINSTALL_CORE_LIBS=ON -DVIRGIL_CRYPTO_FEATURE_PYTHIA=ON \
    && cmake --build _build --target install

# v4
RUN go get -d gopkg.in/virgilsecurity/virgil-crypto-go.v4 \
    && cp -r virgil-crypto/_install/* $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4

# v5
RUN go get -d gopkg.in/virgilsecurity/virgil-crypto-go.v5 \
    && cp -r virgil-crypto/_install/* $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5

# cleanup
RUN rm -rf virgil-crypto
