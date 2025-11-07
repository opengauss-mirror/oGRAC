FROM {{ .Values.images.ograc_base }}

ARG user=ogdba
RUN useradd -m ${user} -u 5000
WORKDIR /ogdb/ograc_install
RUN rm -rf *

COPY oGRAC_2*_RELEASE.tgz .
COPY DBStor_Client_*_RELEASE.tgz .

RUN tar -zxf oGRAC_2*_RELEASE.tgz && rm -rf oGRAC_2*_RELEASE.tgz && \
    cp DBStor_Client_*_RELEASE.tgz ograc_connector/repo && \
    rm -rf DBStor_Client_*_RELEASE.tgz && \
    jq '. + {"ograc_in_container": "1", "link_type": "1"} ' ograc_connector/action/config_params.json > temp && mv temp ograc_connector/action/config_params.json && \
    sed -i "s/\"deploy_user\": \"ogdba:ogdba\"/\"deploy_user\": \"${user}:${user}\"/" ograc_connector/action/config_params.json && \
    cd ograc_connector/action && sh appctl.sh install config_params.json

RUN ln -s /ogdb/ograc_install/ograc_connector/action/docker/ograc_initer.sh /usr/local/bin/ograc-init && \
    chmod +x /ogdb/ograc_install/ograc_connector/action/docker/ograc_initer.sh

CMD ["ograc-init"]