import json
import os, glob
import base64
import boto3
import requests
from cfn_tools import load_yaml, ODict
from yaml import safe_load, load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

## Snippet is for example purposes only ##

######################################################################################
# GitHub - issue creator for the Devops Pipeline Lifecycle Manager (PLM) Service
#
# 1. Create list of all wheel repos from archetype-template type wheel
# 2. Check issues list for PLMTitle="Automatically generated readme.md from template.yml has been provided by PLM"
# - Sets flag to update issue if the issue already exists.
# 3. Get readme.md - confirm it exists and is not the boiler plate
# - Continue to next repo if readme has been updated from the original archetype template (boiler plate).
# 4. Get content of template.yml
# 5. Run cfn readme generator
# 6. Create or update issue on repo.
#
########################################################################################

def load_secret(SecretId,SecretKey):
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(
        SecretId = str(SecretId)
    )
    secret = json.loads(response["SecretString"])[str(SecretKey)]
    return secret

def ghe_request(request_path,bauth,page=1):
    # application/vnd.github.v3+json  /  application/vnd.github.baptiste-preview+json
    headers = {
        "Accept": "application/vnd.github.baptiste-preview+json",
        "Authorization": f"Basic {bauth}"
    }
    payload= {
        "per_page": "100",
        "page": str(page),
        "direction": "desc"
    }
    r = requests.get(f"https://www-github3.A_Company.com/api/v3/{request_path}",headers=headers,params=payload)

    ## Debug lines for troubleshooting
    # print (r)
    # print ( json.loads(r.content.decode()) )
    # #Pretty json formatted results
    # json_formatted_str = json.dumps(json.loads(r.content.decode()), indent=2)
    # print(json_formatted_str)

    if(r.ok):
        return json.loads(r.content.decode())
    return "none"

def ghe_issues(request_path,bauth,issueState="all"):
    # application/vnd.github.v3+json  /  application/vnd.github.baptiste-preview+json
    headers = {
        "Accept": "application/vnd.github.baptiste-preview+json",
        "Authorization": f"Basic {bauth}"
    }
    query = f"?state=all&creator='cx-svc-account-gen'"

    r = requests.get(f"https://www-github3.A_Company.com/api/v3/{request_path}?state={issueState}&creator=cx-svc-account-gen",headers=headers)

    if(r.ok):
        return json.loads(r.content.decode())
    return "none"

def ghe_post(request_path,bauth,payload):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Basic {bauth}"
    }

    r = requests.post(f"https://www-github3.A_Company.com/api/v3/{request_path}",headers=headers,json=payload)

    if(r.ok):
        return json.loads(r.content.decode())
    return "none"

def ghe_patch(request_path,bauth,payload):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Basic {bauth}"
    }

    r = requests.patch(f"https://www-github3.A_Company.com/api/v3/{request_path}",headers=headers,json=payload)

    if(r.ok):
        return json.loads(r.content.decode())
    return "none"

def get_org_repos(bauth,org):
    temp_list = []
    repo_list = []
    repo_data = []
    pagenum = 1
    moredata = True
    request_path = (f"orgs/{org}/repos")
    #print('Repo data fetch', repo_data )
    while moredata == True:
        repo_data = ghe_request(request_path,bauth,pagenum)
        #print (f'repo_data', repo_data)
        temp_list = [data['name'] for data in repo_data]
        repo_list.extend(temp_list)
        #print (f"Temp list {temp_list}")
        #print(f"Getting 100 repos on page {pagenum}" )
        pagenum += 1
        if len(repo_data) < 100:
            moredata = False

    print(f'Number of repos in CXE: ', len(repo_list))
    return repo_list

def readme_generator(tfile='/tmp/template.yml'):

    # Readme_Generator has leveraged the work of gchappel from this repo
    # https://www-github3.A_Company.com/cxe/cf-parameters-to-markdown

    #arg_parser = argparse.ArgumentParser(description="stuff")
    # arg_parser.add_argument("--file", type=argparse.FileType(), required=True, nargs=1,
    #                         help='filename of your CloudFormation template')
    # arguments = arg_parser.parse_args()

    parameters_table = []
    parameters_table.append("| Name | Type | Description | Allowed values |")
    parameters_table.append("|------|------|-------------|----------------|")

    outputs_table = []
    outputs_table.append("| Name | Description | Exported as |")
    outputs_table.append("|------|-------------|-------------|")

    resource_table = []
    resource_table.append("| Resource Name   | Type        |")
    resource_table.append("|-----------------|-------------|")

    cfn_template = load_yaml(open(tfile, "r"))
    if not cfn_template.get('AWSTemplateFormatVersion'):
      print("Error - {tfile} not a valid CloudFormation template")
      #logging.critical("not a valid CloudFormation template")
      #sys.exit(1)
      return

    if cfn_template.get('Parameters'):
      for Parameter in cfn_template.get('Parameters'):
          parameter_name = Parameter
          parameter_description = cfn_template.get("Parameters").get(Parameter).get("Description")
          parameter_type = cfn_template.get("Parameters").get(Parameter).get("Type")
          parameter_default = cfn_template.get("Parameters").get(Parameter).get("Default")
          parameter_allowed_values = ""
          if type(cfn_template.get("Parameters").get(Parameter).get("AllowedValues")) == list:
            for value in cfn_template.get("Parameters").get(Parameter).get("AllowedValues"):
              if value == parameter_default:
                parameter_allowed_values = parameter_allowed_values + "- **{value}** <br />".format(value=value)
              else:
                parameter_allowed_values = parameter_allowed_values + "- {value} <br />".format(value=value)
          parameters_table.append("| {name} | {type} | {description} | {allowed_values} |".format(name=parameter_name, type=parameter_type, description=parameter_description, allowed_values=parameter_allowed_values))

    if cfn_template.get('Resources'):
      for Resource in cfn_template.get('Resources'):
        if type(cfn_template.get("Resources").get(Resource)) == list:
          for value in cfn_template.get("Resources").get(Resource):
            resource_name = Resource
        else:
          resource_name = Resource #cfn_template.get("Resources").get(Resource)

        if type(cfn_template.get("Resources").get(Resource).get("Type")) == list:
          for value in cfn_template.get("Resources").get(Resource).get("Type"):
            resource_type = value
        else:
          resource_type = cfn_template.get("Resources").get(Resource).get("Type")
        resource_table.append("| `{name}` | `{type}` |".format(name=resource_name,type=resource_type))

    if cfn_template.get('Outputs'):
      for Output in cfn_template.get('Outputs'):
          output_name = Output
          output_description = cfn_template.get('Outputs').get(Output).get("Description")
          if cfn_template.get('Outputs').get(Output).get("Export"):
            output_exported_as = cfn_template.get('Outputs').get(Output).get("Export").get("Name")
          else:
            output_exported_as = None
          outputs_table.append("| {name} | {description} | {exported_as} |".format(name=output_name, exported_as=output_exported_as, description=output_description))

    with open("/tmp/output.md", "w") as f:
        print("## Input parameters", file=f)
        for line in parameters_table:
            print(line, file=f)
        print(os.linesep, file=f)

        print("## Resources created", file=f)
        for line in resource_table:
            print(line, file=f)
        print(os.linesep, file=f)

        print("## Output values", file=f)
        for line in outputs_table:
            print(line, file=f)
        print(os.linesep, file=f)


    # with open('/tmp/output.md', 'r') as f:
    #     print ('output file contents')
    #     print(f.read())

    return f


##########################
#
#  Main Handler Function
#
##########################

def handler(event, context):
    org = "cxe"
    #print('Loading token from secretsmanager')
    token = load_secret('/github/webhook_token','token')    # Get GHE PAT
    auth = f"{token}:{token}"
    bauth = base64.b64encode(auth.encode()).decode()
    testing="false" # change to true/false to limit repos and issue creation
    issues=[]
    wheel_repos=""
    repo_list = []
    tire_repos = []
    car_repos = []
    wheel_repos=[]
    skipped = []

##### Get all Repositories in CXE Org
    print (" ** GET ALL REPOSITORIES IN CXE ORG **")

    ### Test lists
    if testing == "true":
        repo_list = ['cx-testing-tire','cx-sample-lambda','cx-app-composite-product','cx-test-datalake-portfolio','cx-generic-lambda-product','cx-testing-tire','cxdl-sc-meraki-event-prov','cx-ghe-webhook-product','cx-test-datalake-portfolio','cway-docs']
    else:
        repo_list = get_org_repos(bauth,org)
        print (f'repos', repo_list)

######  Get all Repositories with 'template_repository'
    print ("** GET ALL REPOSITORIES WITH 'template_repository'  **")
    print (f"Repo list {[repo_list]}")

    if testing != "true":
        for repo in repo_list:
            request_path = (f"repos/{org}/{repo}")
            repo_data = ghe_request(request_path,bauth,1)
            #print (repo_data)

            if repo_data['template_repository'] != None:
                if repo_data['template_repository']['name'] == 'cx-archetype-tire' :
                    tire_repos.append(repo_data['name'])
                elif repo_data['template_repository']['name'] == 'cx-archetype-product' :
                    wheel_repos.append(repo_data['name'])
                elif repo_data['template_repository']['name'] == 'cx-archetype-portfolio' :
                    car_repos.append(repo_data['name'])
                else:
                    skipped.append(repo_data['name'])
            else:
              skipped.append(repo_data['name'])

        print(f"Tire Repos : ", len(tire_repos) )
        print(f"Wheel Repos: ", len(wheel_repos) )
        print(f"Car Repos  : ", len(car_repos) )
        print(f"Repos not from cx-archetype template: ", len(skipped) )


### Test lists
    if testing == "true":
        wheel_repos = ['cxdl-sc-consumer-api-ecs-testing-task-product','cx-testing-tire', 'cx-ghe-webhook-product','cx-apigw-sso-token-product', 'cx-amazon-msk-product', 'cx-syd2-demo-product'] 
        #wheel_repos = ['cx-apigw-sso-token-product', 'cxdl-sc-fis-ingst-proc-prov', 'cx-cc-iam-product', 'cxdl-sc-ingestion-job-metadata-product', 'cx-eks-nodegroup-update-product', 'cx-rcc-s3-product', 'cxdl-sc-dnac-proc-product', 'cxdl-sc-dnac-event-product', 'cxdl-sc-mimir-ingst-prov', 'cx-sq-test-1', 'cxdl-sc-process-generic-sm-product', 'cxdl-sc-streaming-ingestion-product', 'cx-eks-nodegroup-upgrade-product', 'cx-eks-daemonset-upgrade-product', 'cxdl-sc-webex-ingestion-product', 'cxdl-sc-subscription-process-sm-product', 'cxdl-sc-sol-hier-process-sm-product', 'cx-lambda-eks-tags-ci-product', 'cx-lfc-wem-integration-product', 'cx-cc-lambda-bucket-product', 'cx-acm-product', 'cxdl-sc-consumer-api-ecs-testing-task-product', 'cx-es-backup-etl-product', 'cxdl-sc-athena-workgroup-product', 'cxdl-sc-dcc-process-sm-product', 'cx-es-backup-init-product', 'cxdl-sc-ingestion-proc-product', 'cx-data-backup-composite-product', 'cx-controlpoint-logs-s3-product', 'cxdl-sc-consumer-lambda-crawler-product', 'cx-data-backup-service-product', 'cx-generic-events-rule-product', 'cx-acm-crossaccount-cert-product', 'cxdl-sc-consumer-glue-job-trigger-product', 'cx-dns-assume-role-product', 'cx-sc-elasticache-subnet-group-product', 'cxdl-sc-meraki-event-product', 'cx-eks-resources-fluentd-cloudwatch-product', 'cx-chd-attachvpclambda-product', 'cxdl-sc-event-sns-product', 'cxdl-sc-consumption-vpc-peering-product', 'cx-generic-lambda-product', 'cxdl-sc-consumer-lambda-glue-sns-product', 'cx-lambda-ci-eks-upgrade-product', 'cxdl-sc-data-event-product', 'cx-eks-dataplane-upgrade-product', 'cx-eks-controlplane-upgrade-product', 'cx-asset-import-etl-composite-product', 'cx-asset-import-etl-product', 'cxdl-sc-processing-glue-elasticache-redis-connection-product', 'cx-asset-import-init-composite-product', 'cx-asset-import-init-product', 'cx-sample-lambda-product', 'cx-data-security-groups-product', 'cx-api-gateway-product', 'cxdl-sc-elasticache-redis-product', 'cx-asset-export-etl-composite-product', 'cx-asset-export-etl-product', 'cx-lambda-container-ci-product', 'cx-lambda-container-iam-product', 'cxdl-sc-api-ingestion-meraki-product', 'cx-backup-service-product', 'cx-eks-resources-priority-class-product', 'cx-osv-sora-product', 'cx-asset-export-init-composite-product', 'cx-eks-resources-kibana-nginx-product', 'cxdl-sc-common-statemachine-product', 'cxdl-sc-meraki-process-sm-product', 'cxdl-sc-common-sns-policy-product', 'cx-cp-osv-dnac-functions-product', 'cx-cp-osv-dnac-init-product', 'cxdl-sc-meraki-sm-product-do-not-use', 'cx-asset-export-init-product', 'cx-chd-iam-policy-product', 'cx-eks-resources-efs-provisioner-product', 'cx-security-sns-product', 'cxdl-sc-dataset-event-product', 'cx-lambda-container-composite-product', 'cx-lambda-container-product', 'cxdl-sc-consumption-cognito-user-pool-product', 'cx-security-bootstrap-product', 'cx-generic-s3-product', 'cx-umbrella-association-product', 'cx-eks-resources-chartmuseum-product', 'cxdl-sc-ib-processing-statemachine-product', 'cx-route53-recordset-product', 'cxdl-sc-contract-processing-sm-product', 'cxdl-sc-contract-process-sm-product-do-not-use', 'cx-cp-outbound-composite-product', 'cxdl-sc-contract-processing-statemachine-product-do-not-use', 'cxe-cxdl-sc-consumer-glue-connection-product', 'cx-eks-resources-external-dns-product', 'https-www-github3.A_Company.com-cxe-cx-eks-resources-external-dns-product', 'cx-eks-resources-alb-ingress-product', 'cxdl-sc-lifecycle-s3-product', 'cx-cfn-pipeline-test6', 'cxdl-sc-api-ingestion-event-product', 'cx-eks-identity-mapping-product', 'cx-eks-resources-nginx-ingress-product', 'cx-cfn-pipeline-test5', 'cx-elvis-test-product', 'cx-service-linked-role-product', 'cxdl-sc-common-lambda-layer-perm-product', 'cx-eks-resources-composite-product', 'cx-eks-resources-fluxcd-product', 'cxdl-sc-common-s3-bucketpolicy-product', 'cxdl-sc-consumption-glue-job-product', 'cx-regional-waf-product', 'cx-global-waf-product', 'cx-ccc-testdrive-product', 'cx-ccc-test-repo-product', 'cxdl-sc-consumption-glue-crawler-product', 'cx-sc-common-s3globalartifact-provisioning-product', 'cx-eks-resources-product', 'cx-cloud-collector-ecs-fargate-cluster-product', 'cx-cloud-collector-common-composite-product', 'cx-lambda-ibes-presigned', 'cx-lambda-presigned', 'cx-s3event', 'cx-lambda-osv-load-product', 'cx-lambda-ibes-presigned-product', 'cx-lambda-presigned-product', 'cx-rds-with-rotation-composite-product', 'cx-forwarder-composite-product', 'cx-chd-apigw-product', 'cx-cloudfront-distribution-product', 'cp-rmc-composite-product', 'cxdl-sc-iam-managedpolicy-product', 'cxdl-sc-common-managedpolicies-product', 'cx-rds-rotation-product', 'cx-eks-nodegroup-composite-product', 'cx-ccc-composite-product', 'cx-lambda-osv-extract-product', 'cx-sg-security-tools-product', 'cx-ccc-ecsservices-product', 'cx-s3event-product', 'cxdl-sc-consumer-glue-event-product', 'cx-kms-grant-lambda-product', 'cp-rmc-gensim-product', 'cx-security-group-product', 'cx-ccc-iam-policies-product', 'cx-collector-composite-product', 'cx-forwarder-sfn-product', 'cx-collector-day0-secret-product', 'cx-collector-sfn-ecs-task-definition-product', 'cp-rmc-functions-product', 'cx-lambda-s3-composite-product', 'cx-lambda-s3-bucket-product', 'cx-collector-sfn-ecs-service-product', 'cx-eks-network-lambda', 'cx-lambda-Ibes-Gd-product', 'cx-lambda-contract-product', 'cxdl-sc-teststepfunction-product', 'cx-collector-sfn-ecs-task-def-product', 'cp-rmc-fp-init-product', 'cx-rmc-roles-product', 'cx-forwarder-lambda-event-source-product', 'cx-forwarder-sfn-trigger-product', 'cx-forwarder-iam-roles-product', 'cx-forwarder-ecs-task-definition-product', 'cx-apigw-lambda-composite-product', 'cx-forwarder-sqs-product', 'cx-forwarder-log-groups-product', 'cx-forwarder-iam-policies-product', 'cx-ghe-webhook-product', 'cx-umbrella-dns-product', 'cxdl-sc-consumption-glue-role-product', 'cxdl-sc-kms-shared-cmk-product', 'cx-chd-s3-product', 'cxdl-sc-common-ssm-product', 'cx-app-composite-product', 'cx-msk-product', 'cx-ccc-containerdefinition-product', 'cx-ccc-loggroupname-product', 'cx-lambda-authorizer-product', 'cx-collector-cloudwatch-event-lambda-product', 'cx-cxcp-authorizer-product', 'cx-cp-sso-token-service-product', 'cx-cp-external-okta-auth-product', 'cx-cp-chart-basic-authorizer-product', 'cx-apigw-cors-gen-product', 'cx-collector-pce-lambda-product', 'cx-collector-sfn-lambda-product', 'cx-tgw-routing-composite-product', 'cxdl-sc-processing-lambda-tst-product', 'cxdl-sc-processing-lambda-demo-product', 'cx-combined-policy-product', 'cx-qualys-product', 'cx-collector-task-lambda-product', 'cx-parameter-store-product', 'cx-collector-iam-task-lambda-product', 'cx-apigw-composite-product', 'cx-apigw-external-auth-product', 'cx-apigw-external-product', 'cx-apigw-lifecycle-product', 'cx-apigw-controlpoint-product', 'cx-apigw-connector-product', 'cx-collector-iam-sfn-lambda-product', 'cx-collector-iam-pce-lambda-product', 'cx-collector-iam-ecs-execution-product', 'cx-collector-iam-ecs-task-product', 'cxdl-sc-common-s3curatedpolicy-product', 'cx-collector-db-product', 'cx-enterprisedata-accesslogs-product', 'cx-apigw-syslog-product', 'cx-apigw-rmc-product', 'cx-apigw-rma-product', 'cx-apigw-rcc-product', 'cx-apigw-osv-product', 'cx-apigw-commonsvc-product', 'cx-vpclink-product', 'data-enterprisedata-accesslogs', 'cx-enterprisedata-product', 'cx-data-lambda-package-product', 'cxdl-sc-ibes-event-sns-product', 'cxdl-sc-ibes-snspolicy-product', 'cx-service-discovery-product', 'cx-Cloud-Collector-security-group-product', 'cx-controller-envoy-composite-product', 'cxdl-sc-processing-lambda-layer-product', 'cxdl-sc-processing-lambda-product', 'cx-cp-outbound-product', 'cx-elastic-cache-composite-product', 'cx-elastic-cache-product', 'cx-loggroupname-product', 'cx-ecs-fargate-cluster-product', 'cx-snns-test-product', 'cx-elasticsearch-composite-product', 'cx-cc-cw-group-product', 'cx-envoy-ecs-service-product', 'cx-envoy-iam-policies-product', 'cx-envoy-cloudcollector-nlb-product', 'cx-common-s3-product', 'cx-envoy-task-definition-product', 'cxdl-sc-common-dbschema-update', 'cx-envoy-cloudwatch-log-group-product', 'cxdl-sc-processing-sns-lambda-product', 'cxdl-sc-common-testlambda-product', 'cxe-commonacct-s3', 'cx-delete-sns-product', 'delete-sns-product', 'cx-acmcert-product', 'cx-sns-product', 'cx-sqs-product', 'cx-dms-composite-product', 'cx-postgres-composite-product', 'cxdl-sc-common-sns-subscription-product', 'cxdl-sc-ibes-event-product', 'cx-test-product-s3', 'cx-dms-task-product', 'cx-dms-endpoint-product', 'cx-dms-instance-product', 'cx-dms-iam-product', 'cx-mysql-iam-product', 'cx-chd-iam-role-product', 'cx-collector-lambda-product', 'cxdl-sc-common-s3web-product', 'cxdl-sc-common-ecsfargate-cd-ppln-product', 'cx-kms-grant-product', 'cxdl-sc-consumer-ecs-task-product', 'cx-mysql-composite-product', 'cx-apigw-assets-product', 'cxdl-sc-common-ecs-fargate-cluster', 'cx-rds-product', 'cx-codepipeline-status-hook-product', 'cxdl-sc-common-ecs-fargate-svc-product', 'cxdl-sc-ibes-inventory-processor-product', 'cxdl-sc-processing-aci-fulldd-sm-product', 'cx-sg-elb-web-product', 'cx-testing-tagging', 'cx-eks-nodegroup', 'cx-sg-corp-web-product', 'cxdl-sc-ibes-sfn-product', 'cx-githubtag-product', 'orieder-deprecated-2', 'cxdl-sc-common-iam-role', 'cxdl-sc-common-iam-policy', 'cx-base-infra-composite-product', 'cx-accesslog-s3-product', 'cx-vpcflowlog-s3-product', 'cx-vpc-endpoints-product', 'cx-nacl-product', 'cx-vpc-product', 'cx-ebs-encryption-product', 'cx-delete-default-vpc-product', 'cxdl-sc-processing-pid-lambda-product', 'cxdl-sc-processing-aci-cav-lambda-product', 'cxdl-sc-processing-aci-parquet-sm-product', 'cxdl-sc-processing-aci-zip-sm-product', 'cxdl-sc-processing-notify-lambda-product', 'cxdl-sc-processing-manifest-lambda-product', 'cxdl-sc-processing-fetch-zip-lambda-product', 'cxdl-sc-processing-fetch-cavids-lambda-product', 'cxdl-sc-preprocessing-event-rule-product', 'cxdl-sc-lambda-cd-pipeline-product', 'cxdl-sc-ibes-dynamo-taskexec-product', 'cxdl-sc-ibes-dynamo-proctask-product', 'cx-ec2-database-tunnel-product', 'cxdl-sc-ibes-uploadhandler-product', 'cxdl-sc-common-secretsmanager-product', 'cxdl-sc-api-ingestion-statemachine-product', 'cxdl-sc-api-ingestion-ecs-task-product', 'cx-eks-composite-product', 'cx-eks-cp-logs-product', 'cx-eks-cluster-product', 'cx-eks-iam-product', 'cx-eks-vpc-product', 'cxdl-sc-common-schema-update-lambda-product', 'cxdl-sc-common-aurora-serverless-product', 'cxdl-sc-aci-processing-statemachine-product', 'cxdl-sc-cav-processing-statemachine-product', 'cxdl-sc-pid-processing-statemachine-product', 'cx-log-archive-s3-product', 'cxdl-sc-preprocessing-lambda-product', 'cxdl-sc-processing-glue-role-product', 'cxdl-sc-processing-event-rule-product', 'cxdl-sc-common-glue-job-product', 'cxdl-sc-common-sqs-policy-product', 'cxdl-sc-common-sqs-product', 'cxdl-sc-common-glue-encryption-product', 'cxdl-sc-common-dynamodb-product', 'cx-elasticsearch-product', 'cxdl-sc-common-alb-product', 'cx-tgw-rt-propagation-product', 'cx-tgw-rt-association-product', 'cxdl-sc-csdf-ingestion-event-product', 'cxdl-sc-ingestion-event-product', 'cx-eks-app-infra-product', 'cx-eks-base-infra-product', 'cx-route53-product', 'cx-squid-proxy-product', 'cxdl-sc-ingestion-statemachine-product', 'cxdl-sc-common-cloudtrail-product', 'cxdl-sc-common-s3landingpolicy-product', 'cxdl-sc-common-s3logpolicy-product', 'cxdl-sc-common-cmkartifacts-product', 'cxdl-sc-common-cmklogging-product', 'cxdl-sc-common-cmkcurated-product', 'cxdl-sc-common-cmkraw-product', 'cxdl-sc-common-cmklanding-product', 'cx-tgw-rt-product', 'cxdl-sc-common-ecstaskroles-product', 'cx-tgw-attachment-product', 'cx-resource-share-product', 'cxdl-sc-common-cloudwatch-loggroup-product', 'cx-api-gateway-cft', 'cxdl-sc-common-glue-catalog-product', 'cx-tgw-product', 'cx-mysql-product', 'cx-vpc-endpoint-product', 'cxdl-sc-common-s3-product', 'cxdl-sc-common-sns-product', 'cx-tagOptionslibrary-product', 'cxdl-sc-common-cmk-product', 'cxdl-sc-common-log-group-product', 'cxdl-sc-common-ecs-task-product', 'cxdl-sc-common-ecs-task', 'cx-testing-product', 'cx-test-sns-product', 'cx-policy-testing-product', 'cx-provisioning-pipeline', 'cx-tire-for-hub-product', 'cx-testing-new-version-product-2', 'cx-testing-new-version-product', 'cxdl-sc-common-ecs-product', 'cx-sc-ecs-product', 'cx-secretsmanager-test-product', 'cx-nested-product', 'cx-amazon-msk-product', 'cx-syd2-demo-product', 'MyExampleProduct', 'cx-syd-demo-product', 'cx-generic-s3-pipeline-product', 'cx-test-template-product']
        #wheel_repos = ['cx-apigw-sso-token-product', 'cx-amazon-msk-product', 'cx-syd2-demo-product', 'MyExampleProduct', 'cx-syd-demo-product', 'cx-generic-s3-pipeline-product', 'cx-test-template-product']
        #tire_repos =['px-base-infra', 'px-base-infra-bootstrap', 'cxdl-sc-fis-ingst-prov', 'cxdl-sc-ingestion-job-metadata-prov', 'cx-rcc-s3', 'cxdl-sc-dnac-event-prov', 'cxdl-sc-datalake-base-infra', 'cxdl-sc-consumer-api-prov', 'cxdl-sc-consumer-etl-prov', 'cxdl-sc-streaming-ingestion-prov', 'cx-eks-controlplane-upgrade-infra', 'cx-eks-cluster03-upgrade-infra', 'cx-eks-dataplane-upgrade-infra', 'cxdl-sc-dnac-proc-prov', 'cx-core-security-bootstrap', 'cxdl-sc-datalake-bootstrap', 'cxdl-sc-sonoma-prov', 'cxdl-sc-webex-ingst-prov', 'cx-qualys', 'cx-cst-base-infra', 'cx-cst-bootstrap', 'cxdl-sc-landing-bucket-policy-prov', 'cxdl-sc-webex-proc-prov', 'cxdl-sc-consumer-etl-sbx-prov', 'cxdl-sc-consumer-api-sbx-prov', 'cxdl-sc-consumer-ecs-sbx-prov', 'cx-lfc-wem-integration-tire', 'cxdl-sc-consumer-db-sbx-prov', 'cxdl-sc-consumer-db-prov', 'cx-acm', 'cxdl-sc-athena-workgroup-prov', 'cxdl-sc-consumer-testing-provisioning', 'cx-es-backup-etl', 'cx-es-backup-init', 'cx-pipeline-base-infra-bootstrap', 'cx-core-log-archive', 'cx-ec2-database-tunnel-tire', 'cx-app-infra-backup-service', 'cxdl-sc-base-ing-prov', 'cx-controlpoint-logs-s3', 'cx-acm-crossaccount-certificate', 'cx-acm-crossaccount-assume-role', 'cxdl-sc-meraki-event-prov', 'cx-asset-import-etl-infra', 'cx-asset-import-init-infra', 'cx-eks-resources-cluster03-infra', 'cxdl-sc-process-elasticache-redis-sbx-prov', 'cx-eks-cluster-03-infra', 'cx-plm-infra-prov', 'cx-asset-export-etl-tire', 'cxdl-sc-data-event-prov', 'cx-app-infra-tire', 'cx-sample-lambda', 'cx-app-infra-bootstrap', 'cx-asset-export-init-tire', 'cx-api-gateway', 'cx-finops', 'cx-pipeline-cloud-collector', 'cxdl-sc-base-app-sbx-prov', 'cxdl-sc-datalake-sbx-bootstrap', 'cx-cloudfront-distribution', 'cx-eks-lambda-container-infra', 'cx-eks-resources-cluster02-infra', 'cx-osv-sora-aps2', 'cx-eks-infra-temp', 'cxdl-sc-datalake-sbx-base-infra-prov', 'cx-cp-osv-dnac-functions-tire', 'cx-sample', 'cx-iam-roles-policies', 'cxdl-sc-consumer-provisioning', 'cx-cp-osv-dnac-init-tire', 'cp-rmc-tire', 'cxdl-sc-meraki-ingst-prov', 'cx-app-infra-elastic-cache-tire', 'cx-pipeline-base-infra', 'cxdl-sc-processing-meraki-prov', 'cx-css-base-infra', 'cx-css-bootstrap', 'cx-test-hub-prov-pipeline', 'cx-app-infra-elasticsearch-tire', 'cx-pipeline-test-temp', 'cx-core-shared-services', 'cx-chd-lambda-test', 'cx-umbrella-dns', 'cx-sample-product', 'cxdl-sc-ingst-job-table-prov', 'cp-rmc-init-tire', 'cx-security-bootstrap', 'cxdl-sc-dataset-event-prov', 'cx-chd-lambdas-test-legacy', 'cx-chd-snstopic-test-aps2', 'cx-chd-rds-test-aps2', 'cx-app-infra-rds-products-tire', 'cx-chd-apigw-test-aps2', 'cx-apigw-aps2', 'cx-app-infra-cp-outbound-tire', 'cxdl-sc-api-ingst-event-prov', 'cxdl-sc-process-sbx-prov', 'cxdl-sc-preprocess-sbx-prov', 'cx-sc-consumption-glue-cloudwatch-sns-pub-product', 'cx-prd-network-squid-usw2', 'cx-core-network-base-infra-usw2', 'cx-test-product-sq', 'cx-log-archive-s3-usw2', 'cx-global-waf-use1', 'cxdl-sc-ingestion-event-prov', 'cx-eks-resources-infra-aps2', 'cx-sc-sre-sandbox-vpc-prov', 'cx-apigw-lambda-aps2', 'cx-nprd-data-bootstrap-aps2', 'cx-regional-waf-aps2', 'cxdl-sc-process-prov', 'cx-test-prov-pipeline-versions', 'cxdl-sc-preprocess-prov', 'cx-cfn-pipeline-test4', 'cx-eks-infra-nodegroup-aps2', 'cxdl-sc-ibes-process-prov', 'cxdl-sc-pid-proc-prov', 'cxdl-sc-pid-ingst-prov', 'cxdl-sc-pas-proc-prov', 'cxdl-sc-pas-ingst-prov', 'cxdl-sc-intersight-proc-prov', 'cxdl-sc-intersight-ingst-prov', 'cxdl-sc-csdf-proc-prov', 'cxdl-sc-cavid-proc-prov', 'cxdl-sc-ingestion-aio', 'cx-cfn-pipeline-test3', 'cxdl-sc-datalake-bootstrap-prov', 'cx-nprd-kms-grant-aps2', 'cxdl-sc-base-app-prov', 'cx-cst-base-infra-aps2', 'cx-cst-bootstrap-aps2', 'cx-tgw-usw2', 'cx-route53-domain-aps2', 'cx-cfn-pipeline-test2', 'cx-s3event-infra', 'cx-cfn-pipeline-test', 'cx-tgw-aps2', 'cx-core-network-bootstrap-aps2', 'cx-nprd-network-squid-usw2', 'cx-nprd-network-bootstrap-usw2', 'cx-nprd-network-base-infra-usw2', 'cxdl-sc-processing-teststepfunction-prov', 'cx-lambda-s3-aps2', 'cx-qualys-aps2', 'qualys-aps2', 'cx-app-infra-aps2', 'cx-A_Company-hosted-data-aps2', 'cx-cloud-collector-aps2', 'cx-app-infra-data-products-tire', 'cx-enterprisedata-accesslogs', 'cx-data-mysql', 'cxdl-sc-s3-serverless-prov', 'cx-data-lambda-package', 'cx-data-bootstrap-aps2', 'cx-test-wheel-provisioning', 'cx-dummy-prov', 'cx-eks-infra-aps2', 'cx-tgw-ap-southeast-2', 'cx-tgw-resource-share-us-west-2', 'cx-eks-infra', 'cx-nprd-network-bootstrap-aps2', 'cx-codepipeline-status-hook', 'cxdl-sc-intersight-process-prov', 'cxdl-sc-intersight-ingest-prov', 'cxdl-sc-ecsfargate-svc', 'cxdl-sc-pas-ingestion-provisioning', 'cxdl-sc-pas-processing-provisioning', 'cxdl-sc-pid-processing-provisioning', 'cxdl-sc-preprocessing-prov', 'orieder-deprecated-3', 'cx-base-infra-aps2', 'cx-base-infra-bootstrap-aps2', 'cxdl-sc-ibes-processing-prov', 'cx-log-archive-s3-aps2', 'cxdl-sc-cavid-ingestion-provisioning', 'cx-nprd-squid-aps2', 'cxdl-sc-common-s3website-product', 'cxdl-sc-pid-ingestion-provisioning', 'cxdl-sc-processing-prov', 'cx-tgw-us-west-2', 'cx-base-infra-core-accounts', 'cxdl-sc-consumer-prov', 'cxdl-sc-datalake-base-infra-prov', 'cxdl-sc-base-ingestion-provisioning', 'cxdl-sc-csdf-ingestion-provisioning', 'cx-testing-tire', 'cxdl-sc-ingestion-provisioning', 'cxdl-sc-common-ecs-task-provisioning', 'cx-tagoptions-product', 'cxdl-sc-common-ecs-provisioning', 'cx-test-prov-pipeline', 'jatanton-obsolete-delete-me', 'cx-syd2-demo', 'cx-vpc-base-infra-tire', 'cx-demo-s3-provisioning', 'cx-demo-s3-provisioning-dr']

    print (f'Wheel repos : ', wheel_repos)
    print (f'Tire repos : ', tire_repos)
    all_repos=wheel_repos+tire_repos
    print("All wheel and tire repos")
    print (f'All repos : ', all_repos)

##########
##
## For each repo, confirm issue needs to be created or if it already exists.
##
#########

### Get issues for a repo
# GET /repos/{owner}/{repo}/issues
    reponumber=0
    countrepos=len(all_repos)
    # skipping repos with issue that readme_generator isn't able to process correctly, like empty template file.  
    # See issue for description: https://www-github3.A_Company.com/cxe/cx-plm-infra-prov/issues/32 & https://www-github3.A_Company.com/cxe/cx-plm-infra-prov/issues/29
    skip_repo=['cxdl-sc-common-statemachine-product', 'cx-test-template-product', 'cx-cfn-pipeline-test5', 'cx-cfn-pipeline-test6', 'cx-cfn-pipeline-test2', 'cx-cfn-pipeline-test', 'cx-elasticsearch-composite-product' ]

    for repo in all_repos:

        reponumber += 1
        CreateIssue = ""
        PLMIssueFound = "false"
        UpdateIssue = "false"
        GenericReadmeFound = ""
        #issueState="all"
        issueState="open"
        plmtitle="Automatically generated readme.md from template.yml has been provided by PLM"

        if repo in skip_repo:
            print (f'Skippng {repo} number {reponumber} due to issue with generator function.')
            CreateIssue = "false"
            continue

        # Get list of issues for current repo.
        print (f'*** Searching for issues in {repo} / Repo number: {reponumber} of {countrepos}')
        #print (f"request = repos/{org}/{repo}/issues")
        #request_path = (f"repos/{org}/cx-ghe-webhook-product")

        issues = ghe_issues(f"repos/{org}/{repo}/issues",bauth,issueState)
        #print (f"Issues found: {(len(issues))}")

        if len(issues) > 0:
            #print ('Issues found!')
            # If an existing PLM issue is found skip to next repo
            #print(f"*ISSUES:*")
            numberofplmissues=0
            for i in issues:
                #print(f"********\nTitle: {i['title']},\nLabels : {i['labels']},\nState: {i['state']},\nIssue Number : {i['number']} ")
                # print(f'Title:', i['title'])
                # print (plmtitle)
                if i['title'] == plmtitle:
                    PLMIssueFound = "true"
                    UpdateIssue = "true"
                    IssueNumber = i['number']
                    numberofplmissues+=1

            print(f'Number of issues with PLM titles', numberofplmissues)
            if numberofplmissues > 1:
                payload= {"state": "closed" }

                closed = ghe_patch(f"repos/{org}/{repo}/issues/{IssueNumber}",bauth,payload)
                print (f'closing issue: {IssueNumber}' )

        else:
            #PLMIssueFound = "false"
            print (f'PLM Issue Found =', PLMIssueFound)
            ########### GET readme.md
            #print (f'* Searching for readme in {repo}')
            #print (f"request = repos/{org}/{repo}/contents/README.md")
            readme = ghe_request(f"repos/{org}/{repo}/contents/README.md",bauth)
            # #print ("Results for get readme", readme)
            #print (type(readme))
            #print(readme['content'])
            if readme != 'none':
                readme_content = (base64.b64decode(readme['content']).decode("utf-8"))
                #print ("Readme Content & Type", readme_content)
                #print (type(readme_content))

                matches = ["Archetype", "cx-wheel-product"]
                if any(x in readme_content for x in matches):
                    print (f"Readme matches {matches} found in Archetype readme.")
                    print ("Boiler plate detected. Creating an issue.")
                    GenericReadmeFound = "true"
                else:
                    print ("Readme has already been customized, continue to next")
                    GenericReadmeFound = "false"
                    continue
            else:
                continue

            #########################################################
            ## Check if we need to create an issue.
            ## Create issue if PLMIssueFound = false and GenericReadmeFound = true

            print (f"PLM Issue Found =", PLMIssueFound, "and Generic Readme Found =", GenericReadmeFound)
            if PLMIssueFound == "false" and GenericReadmeFound == "true":
                print (f"Setting create issue to true.")
                CreateIssue = "true"
            else:
                print (f"Create issue equals false.")
                CreateIssue = "false"
                UpdateIssue = "true"

        if CreateIssue == "true" or UpdateIssue == "true":

            #########################################################
            #### GET template.yml
            #print (f'* Searching for template in {repo}')
            template = ghe_request(f"repos/{org}/{repo}/contents/template.yml",bauth)
            if template != 'none':
                template_content = base64.b64decode(template['content'])
            ### create tmp file for template.yml
            with open("/tmp/template.yml", "wb") as binary_file:
                binary_file.write(template_content)


            #########################################################
            ### Generate readme from template.yml file in repo ######
            templateReadme = readme_generator("/tmp/template.yml")

            with open('/tmp/output.md', 'r') as f2:
                templateReadmedata = f2.read()
                #print(templateReadmedata)

            #print (f'Prepare issue payload for {repo}')
            payload = {
                    "title":"Automatically generated readme.md from template.yml has been provided by PLM",
                    "body": f"The existing README.md in the repository has not been updated from the default Archetype Template provided boilerplate text.  An updated README.md has been generated from the template.yml file. Please consider either updating or replacing the existing README.md with this auto-generated text, or add a new file to the repo, template-readme.md\n*******\n```\n1. Click ... on titlebar of issue to edit text then copy the issue body.\n2. Replace/update your README.md file and close this issue.\n```\n******* \n\n{templateReadmedata}",
                    "labels": [{"name": "PLMv1"}]
            }

            if CreateIssue == "true":
                i = ghe_post(f"repos/{org}/{repo}/issues",bauth,payload)
                print (f'Creating issue for repo - {repo}')

            elif UpdateIssue == "true":
                #print( f'ghe_patch("repos/{org}/{repo}/issues/{IssueNumber}",bauth,payload)' )
                i = ghe_patch(f"repos/{org}/{repo}/issues/{IssueNumber}",bauth,payload)
                print (f'Updating issue for repo - {repo}')

        #If neither CreateIssue == "true" or UpdateIssue == "true" then continue to next repo
        else:
            print ('Neither CreateIssue or UpdateIssue is true. Next repo.......')
