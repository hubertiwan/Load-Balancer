# Etap budowania: pelny toolchain, binarki linkowane statycznie (musl),
# zeby etapy koncowe mogly byc FROM scratch.
FROM alpine:3.21 AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY Makefile protocol.h protocol.c loadbalancer.c server.c client.c ./
RUN make CFLAGS="-Wall -Wextra -std=gnu11 -O2 -static"

FROM scratch AS loadbalancer
COPY --from=build /src/loadbalancer /loadbalancer
ENTRYPOINT ["/loadbalancer"]

FROM scratch AS server
COPY --from=build /src/server /server
ENTRYPOINT ["/server"]

FROM scratch AS client
COPY --from=build /src/client /client
ENTRYPOINT ["/client"]
