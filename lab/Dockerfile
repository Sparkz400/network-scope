FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
COPY simulators.py /simulators.py
EXPOSE 21 22 23 80 8080 502 6379 44818 47808/udp
USER nobody
ENTRYPOINT ["python", "/simulators.py", "--bind", "0.0.0.0", "--offset", "0"]
