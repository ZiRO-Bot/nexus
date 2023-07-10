from io import BytesIO
from random import randint
from typing import List

from PIL import Image, ImageOps, UnidentifiedImageError, ImageFilter


def bytes2image(image: bytes) -> Image.Image:
    if image.__sizeof__() > 10 * (2 ** 20):
        raise ValueError("Exceeds 10MB")
    try:
        io = BytesIO(image)
        io.seek(0)
        return Image.open(io)
    except UnidentifiedImageError:
        raise ValueError("Unable to use Image")


def image2bytes(img: Image.Image) -> BytesIO:
    image_bytes = BytesIO()
    img.save(image_bytes, format="png")  # type: ignore
    image_bytes.seek(0)
    return image_bytes


def invert(img_bytes: bytes, fixed: bool = True) -> BytesIO:
    img: Image.Image
    if fixed is True:
        w, h = (401, 401)
        img = bytes2image(img_bytes).resize((w, h), 1)
    else:
        og_img = bytes2image(img_bytes)
        ratio = og_img.height / og_img.width
        w = 401
        h = int(w * ratio)
        img = og_img.resize((w, h), 1)
    img = img.convert("RGB")
    return image2bytes(ImageOps.invert(img))


def red(img_bytes: bytes) -> BytesIO:
    img = bytes2image(img_bytes)
    im = img.resize((400, 400), 1)
    w, h = im.size
    red = Image.new("RGBA", (w, h), color=(255, 0, 0, 120))
    im.paste(red, mask=red)
    return image2bytes(im)


def polaroid(img_bytes: bytes, fixed: bool = True) -> BytesIO:
    if fixed is True:
        w, h = (401, 401)
        img = bytes2image(img_bytes).resize((w, h), 1)
    else:
        og_img = bytes2image(img_bytes)
        ratio = og_img.height / og_img.width
        w = 401
        h = int(w * ratio)
        img = og_img.resize((w, h), 1)
    W, H = (w + 29, h + 29)
    blank = Image.new("RGBA", (W, H + 80), color=(255, 255, 255, 255))
    blank.paste(img, (round(round(W - w) / 2), round(round(H - h) / 2)))
    final = blank
    return image2bytes(final)


def sad(img_bytes: bytes) -> BytesIO:
    img = bytes2image(img_bytes)
    im = img.resize((400, 400), 1)
    w, h = im.size
    raindrop = Image.open("assets/raindrops.png")
    raindrop = raindrop.convert("RGBA")
    darken = Image.new("RGBA", (w, h), color=(0, 0, 0, 100))
    im.paste(darken, mask=darken)
    im.paste(raindrop, mask=raindrop)
    return image2bytes(im)


def blurplify(img_bytes: bytes) -> BytesIO:
    img: Image.Image = bytes2image(img_bytes)
    img = img.resize((400, 400), 1)
    w, h = img.size
    blurple = Image.new("RGBA", (w, h), color=(88, 101, 242, 160))
    img.paste(blurple, mask=blurple)
    return image2bytes(img)


def triggered(img_bytes: bytes) -> BytesIO:
    img = bytes2image(img_bytes)
    img = img.resize((500, 500), 1)
    frames: List[Image.Image] = []
    for _frame in range(30):
        canvas = Image.new("RGBA", (400, 400))
        x = -1 * (randint(50, 100))
        y = -1 * (randint(50, 100))
        canvas.paste(img, (x, y))
        red = Image.new("RGBA", (400, 400), color=(255, 0, 0, 80))
        canvas.paste(red, mask=red)
        # Add triggered thingy
        trig: Image.Image = Image.open("assets/triggered.png")
        trig = trig.convert("RGBA")
        canvas.paste(trig, mask=trig)
        frames.append(canvas)
    byteArray = BytesIO()
    frames[0].save(
        byteArray,
        format="GIF",
        save_all=True,
        duration=60,
        loop=0,
        append_images=frames,
    )
    byteArray.seek(0)
    return byteArray


def blur(img_bytes: bytes, fixed: bool = True) -> BytesIO:
    img = bytes2image(img_bytes)
    if fixed:
        img = img.resize((500, 500), 1)
    blur = ImageFilter.GaussianBlur(radius=20)
    img = img.filter(blur)
    return image2bytes(img)


if __name__ == "__main__":
    with open("origin.png", "rb") as in_:
        imgBytes = in_.read()
        changed = blur(imgBytes)

    with open("changed.png", "wb") as out_:
        out_.write(changed.read())
