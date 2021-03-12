FROM rustlang/rust:nightly AS build
COPY . .
RUN echo $KEYCLOAK_PROXY_PORT
RUN cargo build --release

FROM opensuse/leap:latest
COPY --from=build ./target/release/keycloak_proxy ./
CMD RUST_LOG=info ./keycloak_proxy
