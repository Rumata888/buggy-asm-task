FROM gcc:10.3.0 as builder
RUN apt update && apt install git
WORKDIR /lib_build/
RUN git clone https://github.com/Rumata888/aztec-2
WORKDIR /lib_build/aztec-2/barretenberg
COPY ./task.patch  /lib_build/aztec-2/barretenberg
COPY ./builder.sh  /lib_build/aztec-2/barretenberg
RUN chmod +x builder.sh && ./builder.sh

FROM python:3.10-slim
RUN apt update && apt install libstdc++6
RUN pip3 install pycryptodome
RUN groupadd -r crypto && useradd -r -u 1001 -g crypto crypto

RUN mkdir -p /home/crypto
RUN chown -R crypto /home/crypto
USER crypto

COPY dh_support.py /home/crypto
COPY client.py /home/crypto
COPY --from=builder /lib_build/aztec-2/barretenberg/libdh.so /home/crypto
WORKDIR /home/crypto

CMD ["python3","/home/crypto/client.py", "cryptotraining.zone", "1353"]