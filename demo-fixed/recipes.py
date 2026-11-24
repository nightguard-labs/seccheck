import os
import sqlite3
import sys


def db(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS recipes (name TEXT, body TEXT)")
    return con


def main():
    path, cmd, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    con = db(path)
    if cmd == "add":
        con.execute("INSERT INTO recipes VALUES (?, ?)", (args[0], args[1]))
        con.commit()
    elif cmd == "find":
        word = args[0].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        for (name,) in con.execute("SELECT name FROM recipes WHERE name LIKE ? ESCAPE '\\'", (f"%{word}%",)):
            print(name)
    elif cmd == "show":
        base = os.path.realpath("captions")
        target = os.path.realpath(os.path.join(base, args[0]))
        if not target.startswith(base + os.sep):
            sys.exit("not allowed")
        with open(target) as f:
            print(f.read())


if __name__ == "__main__":
    main()
