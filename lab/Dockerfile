FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
COPY simulators.py /simulators.py
EXPOSE 21 22 23 80 8080 502 6379 44818 47808/udp
USER nobody
ENTRYPOINT ["python", "/simulators.py", "--bind", "0.0.0.0", "--offset", "0"]
