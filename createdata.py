from app import db, User, Item
from faker import Faker
from sqlalchemy.exc import IntegrityError
import random

fake = Faker()

users = []
items = []

for _ in range(10):
    user = User(
        username=fake.user_name() + " Username",
        password_hash = 'password',
        last_name=fake.last_name(),
        first_name=fake.first_name(),
        email=fake.email(),
        )
    db.session.add(user)
    users.append(user)

db.session.commit()

for _ in range(10):
    item = Item(
        item_name = fake.name(),
        item_price = fake.price(),
        description = fake.sentence(),
    )
    db.session.add(item)
    items.append(item)

db.session.commit()

for i in range(len(items)):
    for j in range(len(users)):
        if(random.randint(0,1) == 1):
            items[i].users.append(users[j])
            db.session.add(items[i])

db.session.commit()
print("done")
