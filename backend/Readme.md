
```
backend
├─ alembic
│  ├─ env.py
│  ├─ README
│  └─ script.py.mako
├─ alembic.ini
├─ dockerfile
├─ news_database.db
├─ pytest.ini
├─ requirements.txt
├─ src
│  ├─ auth
│  │  ├─ config.py
│  │  ├─ schemas.py
│  │  ├─ services.py
│  │  ├─ utils.py
│  │  └─ __pycache__
│  ├─ config.py
│  ├─ crawler
│  │  ├─ crawler_base.py
│  │  ├─ exceptions.py
│  │  ├─ udn_crawler.py
│  │  ├─ __init__.py
│  ├─ database.py
│  ├─ llm_clients
│  │  ├─ config.py
│  │  ├─ messages.py
│  │  ├─ openai_clients.py
│  │  ├─ openai_clients_base.py
│  │  ├─ __init__.py
│  │  └─ __pycache__
│  ├─ main.py
│  ├─ models.py
│  ├─ news
│  │  ├─ config.py
│  │  ├─ router.py
│  │  ├─ schemas.py
│  │  ├─ services.py
│  │  └─ __pycache__
│  ├─ prices
│  │  ├─ constants.py
│  │  ├─ router.py
│  │  └─ __pycache__
│  ├─ README.md
│  ├─ users
│  │  ├─ constants.py
│  │  ├─ router.py
│  │  └─ __pycache__
│  └─ __pycache__
├─ tests
│  ├─ crawler
│  │  ├─ test_base_crawler.py
│  │  ├─ test_udn_news_crawler.py
│  │  ├─ __init__.py
│  │  └─ __pycache__
│  ├─ integration
│  │  ├─ test_news_endpoint.py
│  │  ├─ test_price_endpoint.py
│  │  ├─ test_user_endpoint.py
│  │  └─ __pycache__
│  ├─ llm_clients
│  │  ├─ test_llm_clients.py
│  │  └─ __pycache__
│  ├─ __init__.py
│  └─ __pycache__
└─ __pycache__


```