import json

data = None

with open('u.json', 'r+') as f:
    data = json.loads(f.read())

username = 'i.amshamim94@gmail.com'
last_index = 0

users = []

for idx, model in enumerate(data):
    fields = model['fields']
    users.append({
        'username': fields['username'],
        'password': fields['password'],
    })
    if fields['username'] == username:
        last_index = idx


with open('user-data.json', 'w+') as f:
    f.write(json.dumps(users[last_index + 1:], indent=4))
