# Week 11: cloud-native detection. Deploy a CloudTrail/GuardDuty/Athena lab,
# ship the logs to Wazuh, emulate attacks with Stratus Red Team, detect them.
#
# The deploy/attack/collect/destroy targets need the bootcamp throwaway AWS
# account. init/validate/fmt/test are credential-free.

.PHONY: init deploy destroy env baseline teardown athena-table test fmt validate

init:
	terraform init

validate:
	terraform validate

fmt:
	terraform fmt -check -recursive

# Stand up the trail, GuardDuty, Athena and the SIEM identity.
deploy:
	terraform init -input=false
	terraform apply -auto-approve

destroy:
	terraform destroy -auto-approve

# Write the SIEM's read-only keys to a git-ignored .env for the Wazuh
# container. The admin keys never touch this file.
env:
	@umask 077; { \
	  echo "AWS_ACCESS_KEY_ID=$$(terraform output -raw siem_access_key_id)"; \
	  echo "AWS_SECRET_ACCESS_KEY=$$(terraform output -raw siem_secret_access_key)"; \
	  echo "TRAIL_BUCKET=$$(terraform output -raw trail_bucket)"; \
	} > .env
	@echo "wrote .env (SIEM read-only keys)"

baseline:
	AWS_REGION=$(or $(AWS_REGION),us-east-1) scripts/snapshot.sh evidence/baseline.txt

teardown:
	AWS_REGION=$(or $(AWS_REGION),us-east-1) scripts/snapshot.sh evidence/teardown.txt

test:
	python3 -m pytest tests/ -q
