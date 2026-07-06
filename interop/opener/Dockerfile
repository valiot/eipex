FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake gcc libc6-dev libcap-dev make ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/EIPStackGroup/OpENer.git /opener
WORKDIR /opener/build
RUN cmake -DOpENer_PLATFORM:STRING=POSIX ../source && make -j"$(nproc)"
CMD ["./src/ports/POSIX/OpENer", "lo"]
