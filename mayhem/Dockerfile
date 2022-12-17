FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libncurses5-dev clang

COPY . /repo
WORKDIR /repo
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_cstring_expand.cpp -fsanitize=fuzzer,address /repo/src/cstring.o -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/mdp /
COPY --from=builder /fuzz /fuzz_cstring_expand
