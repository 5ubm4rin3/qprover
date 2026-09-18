FROM ethereum/solc:0.8.24@sha256:e56ef5e376ae846f06b919d7ca4ed0c271f7fb0900daa6c660d53451f5bfd9db AS solc024

FROM python:3.12.14-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ARG FOUNDRY_VERSION=v1.7.1
ARG FORGE_STD_REV=bf647bd6046f2f7da30d0c2bf435e5c76a780c1b

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential \
    && rm -rf /var/lib/apt/lists/*

ENV FOUNDRY_DIR=/root/.foundry
ENV PATH="${FOUNDRY_DIR}/bin:${PATH}"
ENV QPROVER_SOLC=/usr/local/bin/solc

RUN curl -L https://foundry.paradigm.xyz | bash \
    && foundryup --install "${FOUNDRY_VERSION}" \
    && forge --version \
    && ln -sf "${FOUNDRY_DIR}/bin/forge" /usr/local/bin/forge \
    && ln -sf "${FOUNDRY_DIR}/bin/anvil" /usr/local/bin/anvil \
    && ln -sf "${FOUNDRY_DIR}/bin/cast" /usr/local/bin/cast \
    && ln -sf "${FOUNDRY_DIR}/bin/chisel" /usr/local/bin/chisel

COPY --from=solc024 /usr/bin/solc /usr/local/bin/solc

RUN chmod 0755 /usr/local/bin/solc \
    && /usr/local/bin/solc --version

WORKDIR /opt/qprover
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN python -m pip install --no-cache-dir uv==0.12.11 \
    && uv sync --frozen --no-dev

ENV PATH="/opt/qprover/.venv/bin:${FOUNDRY_DIR}/bin:${PATH}"

COPY trust404 ./trust404
COPY agent ./agent

RUN cd /opt/qprover/trust404/harness \
    && rm -rf lib/forge-std \
    && git clone https://github.com/foundry-rs/forge-std lib/forge-std \
    && cd lib/forge-std \
    && git checkout "${FORGE_STD_REV}" \
    && cd /opt/qprover/trust404/harness \
    && forge build --use /usr/local/bin/solc --offline

ENV TRUST404_HARNESS_DIR=/opt/qprover/trust404/harness
ENTRYPOINT ["python", "/opt/qprover/agent/agent.py"]
