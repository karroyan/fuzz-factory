# 复制为 local_config.py 并填入你自己的值。local_config.py 已被 .gitignore。
# 也可以不建此文件,改用环境变量:OPENAI_BASE_URL / MODEL_KEY_FILE(或 LLM_API_KEY)/ FUZZ_BUNDLE。

BASE_URL = "https://your-openai-compatible-endpoint/v1"   # /chat/completions 端点
MODEL = "glm-5.2"                                          # 模型名
KEY_FILE = "/path/to/your/key_file.py"                    # 内含 api_key='...' 的文件(正则抽取)
BUNDLE = "/path/to/ossfuzz-harbor-bundles/<your-bundle>"  # task bundle 根目录
