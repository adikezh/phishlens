# Helm chart — TODO

Планируемая структура: Chart.yaml, values.yaml (image, config как ConfigMap, секреты через
existingSecret), templates/{deployment,service,ingress,configmap,pvc}.yaml, опциональные
sub-charts ocr и sandbox. Пока используйте deploy/docker-compose.yml.
