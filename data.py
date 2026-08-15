import kagglehub

# Download latest version
path = kagglehub.dataset_download("cyberprince/ai-agent-evasion-dataset")

print("Path to dataset files:", path)