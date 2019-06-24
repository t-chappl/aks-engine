#!/bin/bash

ensureCertificates() {
    AZURESTACK_ENVIRONMENT_JSON_PATH="/etc/kubernetes/azurestackcloud.json"
    AZURESTACK_RESOURCE_MANAGER_ENDPOINT=$(jq .resourceManagerEndpoint $AZURESTACK_ENVIRONMENT_JSON_PATH | tr -d "\"")
    AZURESTACK_RESOURCE_METADATA_ENDPOINT="$AZURESTACK_RESOURCE_MANAGER_ENDPOINT/metadata/endpoints?api-version=2015-01-01"
    curl $AZURESTACK_RESOURCE_METADATA_ENDPOINT
    CURL_RETURNCODE=$?
    KUBE_CONTROLLER_MANAGER_FILE=/etc/kubernetes/manifests/kube-controller-manager.yaml
    if [ $CURL_RETURNCODE != 0 ]; then
        # Replace placeholder for ssl binding
        if [ -f $KUBE_CONTROLLER_MANAGER_FILE ]; then
            sed -i "s|<volumessl>|- name: ssl\n      hostPath:\n        path: \\/etc\\/ssl\\/certs|g" $KUBE_CONTROLLER_MANAGER_FILE
            sed -i "s|<volumeMountssl>|- name: ssl\n          mountPath: \\/etc\\/ssl\\/certs\n          readOnly: true|g" $KUBE_CONTROLLER_MANAGER_FILE
        fi

        # Copying the AzureStack root certificate to the appropriate store to be updated.
        AZURESTACK_ROOT_CERTIFICATE_SOURCE_PATH="/var/lib/waagent/Certificates.pem"
        AZURESTACK_ROOT_CERTIFICATE__DEST_PATH="/usr/local/share/ca-certificates/azsCertificate.crt"
        cp $AZURESTACK_ROOT_CERTIFICATE_SOURCE_PATH $AZURESTACK_ROOT_CERTIFICATE__DEST_PATH
        update-ca-certificates
    else
        if [ -f $KUBE_CONTROLLER_MANAGER_FILE ]; then
            # the ARM resource manager endpoint binding certificate is trusted, remove the placeholder for ssl binding
            sed -i "/<volumessl>/d" $KUBE_CONTROLLER_MANAGER_FILE
            sed -i "/<volumeMountssl>/d" $KUBE_CONTROLLER_MANAGER_FILE
        fi
    fi

    # ensureCertificates will be retried if the exit code is not 0
    curl $AZURESTACK_RESOURCE_METADATA_ENDPOINT
    exit $?
}

configureK8sCustomCloud() {
    export -f ensureCertificates
    retrycmd_if_failure 60 10 30 bash -c ensureCertificates
    set +x
    # When AUTHENTICATION_METHOD is client_certificate, the certificate is stored into key valut,
    # And SERVICE_PRINCIPAL_CLIENT_SECRET will be the following json payload with based64 encode
    #{
    #    "data": "$pfxAsBase64EncodedString",
    #    "dataType" :"pfx",
    #    "password": "$password"
    #}
    if [[ "${AUTHENTICATION_METHOD,,}" == "client_certificate" ]]; then
        SERVICE_PRINCIPAL_CLIENT_SECRET_DECODED=$(echo ${SERVICE_PRINCIPAL_CLIENT_SECRET} | base64 --decode)
        SERVICE_PRINCIPAL_CLIENT_SECRET_CERT=$(echo $SERVICE_PRINCIPAL_CLIENT_SECRET_DECODED | jq .data)
        SERVICE_PRINCIPAL_CLIENT_SECRET_PASSWORD=$(echo $SERVICE_PRINCIPAL_CLIENT_SECRET_DECODED | jq .password)

        # trim the starting and ending "
        SERVICE_PRINCIPAL_CLIENT_SECRET_CERT=${SERVICE_PRINCIPAL_CLIENT_SECRET_CERT#"\""}
        SERVICE_PRINCIPAL_CLIENT_SECRET_CERT=${SERVICE_PRINCIPAL_CLIENT_SECRET_CERT%"\""}

        SERVICE_PRINCIPAL_CLIENT_SECRET_PASSWORD=${SERVICE_PRINCIPAL_CLIENT_SECRET_PASSWORD#"\""}
        SERVICE_PRINCIPAL_CLIENT_SECRET_PASSWORD=${SERVICE_PRINCIPAL_CLIENT_SECRET_PASSWORD%"\""}

        KUBERNETES_FILE_DIR=$(dirname "${AZURE_JSON_PATH}")
        K8S_CLIENT_CERT_PATH="${KUBERNETES_FILE_DIR}/k8s_auth_certificate.pfx"
        echo $SERVICE_PRINCIPAL_CLIENT_SECRET_CERT | base64 --decode > $K8S_CLIENT_CERT_PATH
        # shellcheck disable=SC2002,SC2005
        echo $(cat "${AZURE_JSON_PATH}" | \
            jq --arg K8S_CLIENT_CERT_PATH ${K8S_CLIENT_CERT_PATH} '. + {aadClientCertPath:($K8S_CLIENT_CERT_PATH)}' | \
            jq --arg SERVICE_PRINCIPAL_CLIENT_SECRET_PASSWORD ${SERVICE_PRINCIPAL_CLIENT_SECRET_PASSWORD} '. + {aadClientCertPassword:($SERVICE_PRINCIPAL_CLIENT_SECRET_PASSWORD)}' |\
            jq 'del(.aadClientSecret)') > ${AZURE_JSON_PATH}
    fi

    if [[ "${IDENTITY_SYSTEM,,}" == "adfs"  ]]; then
        # update the tenent id for ADFS environment.
        # shellcheck disable=SC2002,SC2005
        echo $(cat "${AZURE_JSON_PATH}" | jq '.tenantId = "adfs"') > ${AZURE_JSON_PATH}
    fi

    # Decrease eth0 MTU to mitigate Azure Stack's NRP issue
    echo "iface eth0 inet dhcp" | sudo tee -a /etc/network/interfaces
    echo "    post-up /sbin/ifconfig eth0 mtu 1350" | sudo tee -a /etc/network/interfaces
    
    ifconfig eth0 mtu 1350

    set -x
}

configureAzureStackInterfaces() {
    NETWORK_INTERFACES_FILE="/etc/kubernetes/network_interfaces.json"
    AZURE_CNI_INTERFACE_FILE="/etc/kubernetes/interfaces.json"

    echo "Generating token for Azure Resource Manager"
    echo "------------------------------------------------------------------------"
    echo "Parameters"
    echo "------------------------------------------------------------------------"
    echo "SERVICE_PRINCIPAL_CLIENT_ID:     ..."
    echo "SERVICE_PRINCIPAL_CLIENT_SECRET: ..."
    echo "SERVICE_MANAGEMENT_ENDPOINT:     $SERVICE_MANAGEMENT_ENDPOINT"
    echo "ACTIVE_DIRECTORY_ENDPOINT:       $ACTIVE_DIRECTORY_ENDPOINT"
    echo "TENANT_ID:                       $TENANT_ID"
    echo "------------------------------------------------------------------------"

    TOKEN=`curl -s --retry 5 --retry-delay 10 --max-time 60 -f -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=$SERVICE_PRINCIPAL_CLIENT_ID" \
        --data-urlencode "client_secret=$SERVICE_PRINCIPAL_CLIENT_SECRET" \
        --data-urlencode "resource=$SERVICE_MANAGEMENT_ENDPOINT" \
        "$ACTIVE_DIRECTORY_ENDPOINT$TENANT_ID/oauth2/token" | \
        jq '.access_token' | xargs`

    if [[ -z "$TOKEN" ]]; then
        echo "Error generating token for Azure Resource Manager"
        exit $ERR_AZURE_STACK_GET_ARM_TOKEN
    fi

    echo "Fetching network interface configuration for node"
    echo "------------------------------------------------------------------------"
    echo "Parameters"
    echo "------------------------------------------------------------------------"
    echo "RESOURCE_MANAGER_ENDPOINT: $RESOURCE_MANAGER_ENDPOINT"
    echo "SUBSCRIPTION_ID:           $SUBSCRIPTION_ID"
    echo "RESOURCE_GROUP:            $RESOURCE_GROUP"
    echo "NETWORK_INTERFACE:         $NETWORK_INTERFACE"
    echo "NETWORK_API_VERSION:       $NETWORK_API_VERSION"
    echo "NETWORK_INTERFACES_FILE:   $NETWORK_INTERFACES_FILE"
    echo "------------------------------------------------------------------------"

    curl -s --retry 5 --retry-delay 10 --max-time 60 -f -X GET \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        "${RESOURCE_MANAGER_ENDPOINT}subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Network/networkInterfaces/$NETWORK_INTERFACE?api-version=$NETWORK_API_VERSION" > $NETWORK_INTERFACES_FILE

    if [[ ! -s $NETWORK_INTERFACES_FILE ]]; then
        echo "Error fetching network interface configuration for node"
        exit $ERR_AZURE_STACK_GET_NETWORK_CONFIGURATION
    fi

    echo "Generating Azure CNI interface file"
    echo "------------------------------------------------------------------------"
    echo "Parameters"
    echo "------------------------------------------------------------------------"
    echo "SUBNET_CIDR:              $SUBNET_CIDR"
    echo "AZURE_CNI_INTERFACE_FILE: $AZURE_CNI_INTERFACE_FILE"
    echo "------------------------------------------------------------------------"

    cat $NETWORK_INTERFACES_FILE | jq "[{MacAddress: .properties.macAddress, IsPrimary: .properties.primary, IPSubnets: [{Prefix: \"$SUBNET_CIDR\", IPAddresses: .properties.ipConfigurations | [.[] | {Address: .properties.privateIPAddress, IsPrimary: .properties.primary}]}]}]" > $AZURE_CNI_INTERFACE_FILE
}