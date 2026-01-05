# Advertisement Service API v2.0

![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=JSON%20web%20tokens&logoColor=white)

Сервис для размещения и управления объявлениями купли/продажи с системой аутентификации и ролями пользователей.

##  Оглавление

- [Особенности](#-особенности)
- [Система ролей](#-система-ролей)
- [Быстрый старт](#-быстрый-старт)
- [API Документация](#-api-документация)
- [Аутентификация](#-аутентификация)
- [Примеры запросов](#-примеры-запросов)
- [Развертывание](#-развертывание)
- [Структура проекта](#-структура-проекта)

##  Особенности

- **JWT аутентификация** с токенами на 48 часов
- **Система ролей**: пользователь (user) и администратор (admin)
- **Полный CRUD** для пользователей и объявлений
- **Гибкий поиск** объявлений с фильтрами
- **Автоматическая документация** Swagger UI и ReDoc
- **Контейнеризация** с Docker Compose
- **Хеширование паролей** с bcrypt
- **Пагинация** и валидация данных

##  Система ролей

###  Неавторизованный пользователь
-  Создание пользователя `POST /user`
-  Получение пользователя по ID `GET /user/{id}`
-  Получение объявления по ID `GET /advertisement/{id}`
-  Поиск объявлений `GET /advertisement?{query}`
-  Аутентификация `POST /login`

###  Авторизованный пользователь (user)
-  Все права неавторизованного пользователя
-  Обновление своих данных `PATCH /user/{id}`
-  Удаление себя `DELETE /user/{id}`
-  Создание объявлений `POST /advertisement`
-  Обновление своих объявлений `PATCH /advertisement/{id}`
-  Удаление своих объявлений `DELETE /advertisement/{id}`
-  Просмотр своих объявлений `GET /me/advertisements`

###  Администратор (admin)
-  Все операции с любыми пользователями
-  Все операции с любыми объявлениями
-  Получение всех пользователей `GET /admin/users`
-  Получение всех объявлений `GET /admin/advertisements`

##  Быстрый старт

### Запуск с Docker Compose

```bash
# 1. Клонируйте репозиторий
git clone <repository-url>
cd advertisement_service

# 2. Запустите приложение
docker-compose up --build

# 3. Приложение доступно по адресу:
#    http://localhost:8000