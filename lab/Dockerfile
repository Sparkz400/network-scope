FROM python:3.12-alpine
COPY simulators.py /simulators.py
EXPOSE 21 22 23 80 8080 502 6379 44818 47808/udp
USER nobody
ENTRYPOINT ["python", "/simulators.py", "--bind", "0.0.0.0", "--offset", "0"]
