FROM debian:8
ENV DEBIAN_FRONTEND noninteractive

RUN echo 'force-unsafe-io' | tee /etc/dpkg/dpkg.cfg.d/02apt-speedup && \
    echo 'DPkg::Post-Invoke {"/bin/rm -f /var/cache/apt/archives/*.deb || true";};' | tee /etc/apt/apt.conf.d/no-cache && \
    echo 'Acquire::http {No-Cache=True;};' | tee /etc/apt/apt.conf.d/no-http-cache


RUN apt-get update && \
    apt-get install -y \
        build-essential \
        libffi-dev \
        && apt-get clean

RUN apt-get install -y \
        python3 \
        python3-dev \
        python3-pip \
	python3-setuptools \
        && apt-get clean


RUN apt-get install -y \
        libfuzzy-dev ssdeep \
        && apt-get clean


RUN pip3 install --upgrade pip setuptools

COPY . /code

RUN pip3 install -r /code/requirements.txt

CMD /code/gitgot.py -q SEARCH-HERE
