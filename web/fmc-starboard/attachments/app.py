from flask import Flask, request, render_template
import psycopg2
from psycopg2.extras import RealDictCursor
import os

app = Flask(__name__)

FLAG = os.environ.get('FLAG', 'maltactf{test_flag}')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:password@postgres:5432/app')

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def seed_db():
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(f'''
DROP TABLE IF EXISTS posts;
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    post VARCHAR(255) NOT NULL,
    stars INT NOT NULL
);

DROP TABLE IF EXISTS flag;
CREATE TABLE IF NOT EXISTS flag (
    flag VARCHAR(255) NOT NULL
);
''')

        cur.executemany('INSERT INTO posts (post, stars) VALUES (%s, %s)', [
            ('🐈 👧 ♟️ 🔛 🔝', 9),
            ('yuo shoudl alos tyr soem bingus', 8),
            ('Can god tell he difference between me and Vaun?', 19),
            ('I spent like 5 hours outside without underwear, just pants', 11),
            ('can\'t spell szymex without sexy', 12),
            ('my coworker today told me that yesterday his son didn\'t want to take a shit cause he was scared that a skibidi was gonna come out of the toilet', 14),
            ('todays gonna be the day i finally use chopsticks to eat at the chinese place on campus and not ask for a fork 😇', 11),
            ('I literally look like :osaka: when i look at mirror rn', 14),
            ('“I need a woman to look at me the way Josh is looking at that beer” - Mixy 1', 9),
            ('one time i ate wax that i thought was cheese', 10),
            ('Its not gambling when you know your gonna win.', 10),
            ('i sometimes feel like im doing something illegal opening this channel', 10),
            ('mixy lost his money in a casino and is sleeping on trixters floor now', 28),
            ('honestly, there\'s like a couple dozen people I wanted to meet up in my time here. had to filter off the lower priority ones. of course you\'re not on the list at all', 19),
            ('liveoverflow ghosted me', 16),
            ('fmc failing to capture a flag? color me surprised', 9),
            ('FMC might have 20 active shitposters but when it comes to actual events you\'ll be lucky if genni shows up to the event he\'s been hyping all week', 15),
            ('the shawarma legend', 10),
            ('our taxi driver called someone to tell them he is driving italians', 14),
            ('I don\'t speak chinese, they give me a stick of meat, I eat it', 14),
            ('for every star, mvm will give away 100 dollars', 32),
            ('im gonna have to learn what an order is💀', 10),
        ])
        cur.execute('INSERT INTO flag (flag) VALUES (%s)', (FLAG,))

    conn.commit()
    conn.close()


@app.route('/', methods=['GET'])
def index():
    order = request.args.get('order', 'DESC')
    if ';' in order or ',' in order:
        return jsonify({'error': 'bad char'})

    conn = get_conn()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f'SELECT * FROM posts ORDER BY stars {order} LIMIT 50')
        results = cur.fetchall()
    conn.close()
    
    return render_template('index.html', posts=results, order=order)

if __name__ == '__main__':
    seed_db()

    app.run(debug=False, host='0.0.0.0', port=1337)