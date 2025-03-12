from elasticsearch import Elasticsearch

es = Elasticsearch(
    ["https://<<YOUR URL>>:9200"],  # Ensure it's HTTPS
    basic_auth=("<<YOUR USERNAME>>", "<<YOUR PASSWORD>>"),
    ca_certs="/etc/ssl/certs/ca.crt"  # Path to the CA certificate
)

try:
    health = es.options(request_timeout=30).cluster.health()
    print("Elasticsearch Cluster Health:", health)
except Exception as e:
    print("Error connecting to Elasticsearch:", e)
