# Eipex

EtherNet/IP (CIP) protocol stack in pure Elixir: scanner (originator) and
adapter (target) roles, explicit and implicit messaging, and Logix tag
services. Design: `docs/superpowers/specs/2026-07-02-ethernet-ip-stack-design.md`.

## Interop testing

`mix test` is hermetic. To run interop tests against the cpppo Logix simulator:

    docker compose -f interop/docker-compose.yml up -d
    mix test --include interop
    docker compose -f interop/docker-compose.yml down

The adapter side is exercised with pycomm3:

    mix test --include interop test/interop/pycomm3_test.exs

The scanner's class 1 I/O is validated against OpENer, the ODVA reference
adapter (builds from source, binds host loopback):

    docker compose -f interop/docker-compose.yml up -d --build opener
    mix test --include interop test/interop/opener_test.exs
    docker compose -f interop/docker-compose.yml down
