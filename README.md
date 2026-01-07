# Advertisement Service API

![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=JSON%20web%20tokens&logoColor=white)

Сервис для размещения и управления объявлениями купли/продажи с аутентификацией JWT и системой ролей.

##  Особенности

-  JWT аутентификация с токенами на 48 часов
-  Безопасное хеширование паролей с bcrypt
-  Система ролей: пользователь и администратор
-  Полный CRUD для пользователей и объявлений
-  Правильные HTTP статус-коды (409 для конфликтов и т.д.)
-  Валидация данных через Pydantic v2

##  Быстрый старт

### Установка и запуск

```bash
# Клонируйте репозиторий
git clone https://github.com/NataliSt-pixel/advertisement_service2.git
cd advertisement_service2

# Установите зависимости
pip install -r requirements.txt

# Запустите сервер
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000