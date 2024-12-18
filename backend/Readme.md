```
backend
├─ .coverage
├─ .pytest_cache
├─ .scannerwork
├─ alembic
│  ├─ env.py
│  ├─ README
│  └─ script.py.mako
├─ alembic.ini
├─ app.log
├─ app_rotating.log
├─ coverage.xml
├─ dockerfile
├─ news_database.db
├─ pytest.ini
├─ README.md
├─ requirements.txt
├─ src
│  ├─ .env
│  ├─ auth
│  │  ├─ config.py
│  │  ├─ exceptions.py
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
│  ├─ exceptions.py
│  ├─ llm_clients
│  │  ├─ anthropic_clients.py
│  │  ├─ config.py
│  │  ├─ exceptions.py
│  │  ├─ llm_base.py
│  │  ├─ openai_clients.py
│  │  ├─ Templete.py
│  │  ├─ __init__.py
│  │  └─ __pycache__
│  ├─ logger
│  │  ├─ base.py
│  │  └─ __pycache__
│  ├─ main.py
│  ├─ models.py
│  ├─ news
│  │  ├─ config.py
│  │  ├─ exceptions.py
│  │  ├─ router.py
│  │  ├─ schemas.py
│  │  ├─ services.py
│  │  └─ __pycache__
│  ├─ prices
│  │  ├─ constants.py
│  │  ├─ exceptions.py
│  │  ├─ router.py
│  │  └─ __pycache__
│  ├─ users
│  │  ├─ constants.py
│  │  ├─ exceptions.py
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