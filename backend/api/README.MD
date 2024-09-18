# Dowell Login API Documentation

**POST** `/api/loginapi/`

Required fields

- api_service_id (The service_id you see in Dowell API services)
- api_key (The key you get from Dowell API services)
- username
- password
- time
- ip
- os
- location
- timezone

Optional fields

- language (If not provided English is submitted to db)
- browser (If not provided empty string is provoded to db)
- device (If not provided, string 'api' is sent to db)

#### Request body

```json
{
  "username": "string",
  "password": "string",
  "api_services": "string",
  "api_key": "sting",
  "time": "string",
  "ip": "string",
  "os": "string",
  "device": "string",
  "location": "string",
  "timezone": "string",
  "language": "string",
  "browser": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string",
  "session_id": "string",
  "remaining_times": "integer"
}
```

- Now this session_id can be used in /userinfo api to get login details.

---

**POST** `/api/password_change/`

Required fields

- username
- old_password
- new_password

#### Request body

```json
{
  "username": "string",
  "old_password": "string",
  "new_password": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```

---

**POST** `/api/userinfo/`
**GET** `/api/userinfo/`

Required fields

- session_id
- product

#### Request body

```json
{
  "session_id": "string",
  "product": "string"
}
```

#### Example response

```json
{
  "userinfo": "array",
  "portfolio_info": "array",
  "userportfolio": "array",
  "members": "object",
  "own_organizations": "array",
  "other_org": "object"
}
```

---

**POST** ` /api/mobilelogin/`

Required fields

- username
- password
- time
- ip
- os
- location
- timezone

Optional fields

- language (If not provided English is submitted to db)
- browser (If not provided empty string is provoded to db)
- device (If not provided, string 'api' is sent to db)

#### Request body

```json
{
  "username": "string",
  "password": "string",
  "location": "string",
  "device": "string",
  "os": "string",
  "time": "string",
  "ip": "string",
  "timezone": "string",
  "browser": "string",
  "language": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string",
  "session_id": "string"
}
```

- Now this session_id can be used in /userinfo api to get login details.

---

**POST** `/api/mobilelogout/`

Required fields

- session_id

#### Request body

```json
{
  "session_id": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```

---

**POST** `/api/emailotp/`

Required fields

- email
- username
- usage
  - "create_account" if you're using this api for register page.
  - "update_email" if you're using this page for profile_update.
  - "forgot_password" for respective page
  - "forgot_username" for respective page.

#### Request body

```json
{
  "email": "string",
  "username": "string",
  "usage": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```

---

**POST** ` /api/forgot_password/`

> You must get the otp from the `/api/emailotp` endpoint with the exact "usage" given in the api documentation.

Required fields

- username
- email
- otp
- new_password

#### Request body

```json
{
  "username": "string",
  "email": "string",
  "otp": "string",
  "new_password": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```

---

**POST** `/api/forgot_username/`

> You must get the otp from the `/api/emailotp` endpoint with the exact "usage" given in the api documentation.

Required fields:

- email
- otp

#### Request body

```json
{
  "email": "string",
  "otp": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```

---

**POST** ` /api/profile_update/`
Required fields:

- username

If you're trying to update email, firstly user must be sent the otp in their email. So, for that:

> You must get the otp from the `/api/emailotp` endpoint with the exact "usage" given in the api documentation.

#### Request body

```json
{
  "email_otp": "string",
  "address": "string",
  "zip_code": "string",
  "user_city": "string",
  "user_location": "string",
  "user_country": "string",
  "native_language": "string",
  "nationality": "string",
  "language_preferences": "string",
  "vision": "string",
  "username": "string",
  "first_name": "string",
  "last_name": "string",
  "email": "string",
  "phone": "string",
  "image": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```

---

**POST** ` /api/user_status/`
Required fields:

- username
- status

#### Request body

```json
{
  "username": "string",
  "status": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```

---

**POST** ` /api/otp_verify/`
This is a central api for generating otp via email and sms. The request is first initaited with username and email or phone number to generate otp.

Required fields:

- username
- email
- phone
- otp ( After otp has been generated)

#### Request body

```json
{
  "username": "string",
  "email": "string",
  "phone": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```

---

**POST** ` /api/all_liveusers/`
Required fields:

- session_id

#### Request body

```json
{
  "session_id": "string"
}
```

#### Example response

```json
{
  "product_wise": "array",
  "weekly_product_wise": "array",
  "users": "array",
  "total Live": "array",
  "Note": "string"
}
```

---

**POST** ` /api/otp_verify/`
This is a central api for generating otp via email and sms. The request is first initaited with username and email or phone number to generate otp.

Required fields:

- username
- email
- phone
- otp ( After otp has been generated)

#### Request body

```json
{
  "username": "string",
  "email": "string",
  "phone": "string"
}
```

#### Example response

```json
{
  "msg": "string",
  "info": "string"
}
```
