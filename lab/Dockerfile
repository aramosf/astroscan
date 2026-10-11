FROM ubuntu:24.04

ARG LIBHEIF_REF=v1.23.1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates clang clang-18 cmake ffmpeg git libaom-dev libclang-rt-18-dev libde265-dev \
      libjpeg-dev libpng-dev libx265-dev ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone --depth 1 --branch "${LIBHEIF_REF}" https://github.com/strukturag/libheif.git

WORKDIR /opt/libheif
RUN cmake -B build -G Ninja \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
      -DWITH_EXAMPLES=ON \
      -DWITH_GDK_PIXBUF=OFF \
    && cmake --build build --target heif-dec

ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
ENTRYPOINT ["/opt/libheif/build/examples/heif-dec"]
