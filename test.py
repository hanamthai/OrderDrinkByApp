import bcrypt
import time
password = "super secret password"
# password = password.encode('utf-8')
print(password)
# Hash a password for the first time, with a randomly-generated salt
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hash)

# Check that an unhashed password matches one that has previously been
print(hashed)
if bcrypt.checkpw(password, hashed):
    print("It Matches!")
else:
    print("It Does not Match :(")
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
time.sleep(2.4)


if bcrypt.checkpw(password, hashed):
    print("It Matches!")
else:
    print("It Does not Match :(")




{
    "drink":
        {
            "category": "Trà Sữa",
            "description": "30 gram trà + 20 gram sữa.",
            "drinkid": 3,
            "drinkimage": "https://channel.mediacdn.vn/thumb_w/640/428462621602512896/2022/10/27/photo-1-1666869235187680523516.jpg",
            "drinkname": "Trà Sữa Thập Cẩm",
            "status": "Available"
        },
    "topping":
    [
        {
            "nametopping": "THẠCH CỦ NĂNG",
            "pricetopping": "$5,000.00",
            "toppingid": 3
        },
        {
            "nametopping": "THẠCH CỦ NĂNG",
            "pricetopping": "$5,000.00",
            "toppingid": 3
        },
        {
            "nametopping": "THẠCH CỦ NĂNG",
            "pricetopping": "$5,000.00",
            "toppingid": 3
        }
    ]
}








{
    "all-drink":
    [
        {
            "category": "Sinh Tố",
            "drinkid": 1,
            "drinkimage": "https://cdn.beptruong.edu.vn/wp-content/uploads/2021/03/sinh-to-bo-dua.jpg",
            "drinkname": "Sinh Tố Bơ",
            "price": "$20,000.00",
            "status": "Available"
        },
        {
            "category": "Caffe",
            "drinkid": 2,
            "drinkimage": "https://123phache.com/wp-content/uploads/2020/02/ca_phe_sua_da-600x600-1.jpg",
            "drinkname": "Caffe Sữa Đá",
            "price": "$25,000.00",
            "status": "Unvailable"
        },
        {
            "category": "Trà Sữa",
            "drinkid": 3,
            "drinkimage": "https://channel.mediacdn.vn/thumb_w/640/428462621602512896/2022/10/27/photo-1-1666869235187680523516.jpg",
            "drinkname": "Trà Sữa Thập Cẩm",
            "price": "$20,000.00",
            "status": "Available"
        }
    ]
}