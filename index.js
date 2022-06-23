require('dotenv').config()
const crypto = require('crypto');

const cors = require('cors');
const fetch = require('node-fetch');
const express = require('express');
const monk = require('monk')

const db = monk(process.env.MONGO_URL || 'localhost/my-ocular-other')
const users = db.get('users')
const stars = db.get('stars')
const reactions = db.get('reactions')
const persistedSessions = db.get('sessions') // used to store user sessions. it gets updated in sync with the sesions array but it is only used to persist sessions over restarts. it is only read from when server starts,

users.createIndex('name', { unique: true })

const app = express()
const port = 8081

const jokes = require('./jokes.json')
const frontendURL = process.env.FRONTEND_URL || 'http://localhost:8000'
const whitelist = ['http://localhost:8000', 'http://localhost:8081', 'https://my-ocular.jeffalo.net', 'https://ocular.jeffalo.net']
const emojis = ['👍', '👎', '😄', '🎉', '😕', '❤️', '🚀', '👀'] // stolen from github. TODO: use emojis that make sense for the forums

const corsOptions = {
    origin: function (origin, callback) {
        if (whitelist.indexOf(origin) !== -1 || !origin) {
            callback(null, true)
        } else {
            callback(new Error('Not allowed by CORS'))
        }
    },
}

app.use(express.json()); //Used to parse JSON bodies

app.options('/api/users', cors(corsOptions)) // enable pre-flight request for user list

app.get('/api/users', cors(corsOptions), async (req, res) => {
    // const page = parseInt(req.query.page) || 0;
    // const userList = await users.find({}, { sort: { _id: -1 }, limit: 15, skip: page * 15 })
    if (typeof req.headers.authorization === 'string') {
        const session = findSession(req.headers.authorization)

        if (typeof session === 'undefined') {
            return res.json({ error: 'invalid auth' })
        }

        const sessionUser = await getUserData(session.name)

        if (!sessionUser.admin) {
            return res.json({ error: `only admins can get a list of users.` })
        }
        const userList = await users.find({}, { sort: { 'meta.updated': -1, _id: -1 } }) // TODO: pagination (see above)
        return res.json(userList)
    }

    res.json({ error: 'you need auth' })
})

app.get('/api/user/:name', cors(), async (req, res) => {
    const noReplace = typeof req.query.noReplace === 'string';
    const user = await getUserData(req.params.name.replace('*', ''))
    const allUsers = await users.find()

    if (!noReplace && user) {
        user.status = user.status.replace(/(?<!\\){joke}/g, jokes[Math.floor(Math.random() * jokes.length)])
        user.status = user.status.replace(/\\({joke})/g, '$1')

        user.status = user.status.replace(/(?<!\\){online}/g, sessions.length)
        user.status = user.status.replace(/\\({online})/g, '$1')

        user.status = user.status.replace(/(?<!\\){total}/g, allUsers.length)
        user.status = user.status.replace(/\\({total})/g, '$1')

        if (user.status.match(/(?<!\\){count}/)) {
            let count = 'error'; // dont use number since it errors
            try {
                const controller = new AbortController();
                const { signal } = controller;
                setTimeout(() => {
                    controller.abort()
                }, 5000) // abort fetch after 5 seconds
                const apiRes = await fetch(`https://scratchdb.lefty.one/v3/forum/user/info/${user.name}`, {
                    signal: signal
                });

                if (apiRes.ok) {
                    const data = await apiRes.json();
                    count = data?.counts?.total?.count?.toString() || 'error';
                }
            } catch {};

            user.status = user.status.replace(/(?<!\\){count}/g, count)
            user.status = user.status.replace(/\\({count})/g, '$1')
        }
    }

    user ? res.json(user) : res.json({ error: 'no user found' })
})

app.options('/api/user/:name', cors(corsOptions)) // enable pre-flight request for updating user

app.put('/api/user/:name', cors(), async (req, res) => {
    if (typeof req.headers.authorization === 'string') {
        const session = findSession(req.headers.authorization)

        if (typeof session === 'undefined') {
            return res.json({ error: 'invalid auth' })
        }

        const sessionUser = await getUserData(session.name)

        if (session.name.toLowerCase() !== req.params.name.toLowerCase() && !sessionUser.admin) {
            return res.json({ error: `editing someone else's status i see.` })
        }

        const user = await getUserData(req.params.name)

        // temporary security fix
        // return res.json({ error: 'for security reasons ocular statuses can not be updated at this time. sorry for the inconvenience' })

        if (user) {
            if (user.banned && !sessionUser.admin) return res.json({ error: `you are banned from ocular. visit https://my-ocular.jeffalo.net/ban-info/${user.name} for more information.` })

            const now = new Date()

            if (sessionUser.admin) {
                // ban user
                if (req.body.banned) {
                    await users.update({ name: user.name }, { $set: { banned: req.body.banned } })
                } else {
                    await users.update({ name: user.name }, { $unset: { banned: '' } })
                }
            }

            await users.update({ name: user.name }, { $set: { status: req.body.status, color: req.body.color, 'meta.updatedBy': sessionUser.name, 'meta.updated': now.toISOString() } })


            return res.json({ ok: 'user updated' })
        } else {
            // this is an admin trying to update the status of a non-existent user. we should create that user with the specified data.

            const scratchResponse = await fetch(`https://api.scratch.mit.edu/users/${req.params.name}/`) // get the proper case of the username instead of whatever admin inputted
            const scratchData = await scratchResponse.json()

            if (typeof scratchData.username === 'undefined') {
                return res.json({ error: 'user not found on scratch' })
            }

            const now = new Date()

            await users.insert({
                name: scratchData.username,
                status: req.body.status,
                color: req.body.color,
                meta: {
                    updated: now.toISOString(),
                    updatedBy: session.name
                }
            })
            return res.json({ ok: 'user added' })
        }
    }
    return res.json({ error: 'you need auth' })
})

app.delete('/api/user/:name', cors(), async (req, res) => {
    if (typeof req.headers.authorization !== 'string') {
        return res.json({ error: 'you need auth' })
    }

    const session = findSession(req.headers.authorization)

    if (typeof session === 'undefined') {
        return res.json({ error: 'invalid auth' })
    }

    const sessionUser = await getUserData(session.name)

    if (!sessionUser.admin) {
        return res.json({ error: 'this action can only be performed by an admin' })
    }

    const user = await getUserData(req.params.name)

    if (typeof user === 'undefined') {
        return res.json({ error: 'no user found. cannot delete' })
    }

    console.log(`${sessionUser.name} is deleting all data for ${user.name}`)

    await reactions.remove({ name: user.name })
    await persistedSessions.remove({ name: user.name })
    await stars.remove({ name: user.name })
    await users.remove({ name: user.name })
    res.json({ ok: 'user gone. :(' })
})

app.get('/api/user/:user/picture', cors(), async (req, res) => {
    const scratchResponse = await fetch(`https://api.scratch.mit.edu/users/${req.params.user}/`)
    const scratchData = await scratchResponse.json()
    const pictureURL = scratchData.profile ? scratchData.profile.images['90x90'] : 'https://cdn2.scratch.mit.edu/get_image/user/0_90x90.png'
    res.redirect(pictureURL)
})

app.options('/api/starred/:id', cors(corsOptions)) // enable pre-flight request for getting star data

app.get('/api/starred/:id', cors(corsOptions), async (req, res) => { // returns whether the logged in user starred a post
    if (typeof req.headers.authorization !== 'string') {
        res.json({ error: 'you need auth' })
    } else {
        const session = findSession(req.headers.authorization)
        if (typeof session !== 'undefined') {
            return res.json({ error: 'invalid auth' })
        }
        const user = await getUserData(session.name)
        if (typeof user === 'undefined') {
            return res.json({ error: 'invalid auth no user found' })
        }

        const starredPost = await stars.findOne({ post: req.params.id, user: user.name })
        // console.log({ starredPost, post: req.params.id, user: user.name})
        starredPost ? res.json({ starred: true }) : res.json({ starred: false })
    }
})

app.options('/api/star/:id', cors(corsOptions)) // enable pre-flight request starring post

app.post('/api/star/:id', cors(corsOptions), async (req, res) => { // stars a post
    if (typeof req.headers.authorization !== 'string') {
        res.json({ error: 'you need auth' })
    } else {
        const session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        const checkRes = await fetch(`https://scratch.mit.edu/discuss/post/${req.params.id}/source/`) // check if the post really exists
        if (!checkRes.ok) {
            return res.json({ error: 'post doesnt exist' })
        }
        const user = await getUserData(session.name)
        if (typeof user === 'undefined') {
            return res.json({ error: 'invalid auth no user found' })
        }
        const starredPost = await stars.findOne({ post: req.params.id, user: user.name })
        if (starredPost) {
            // remove star
            await stars.remove(starredPost._id)
            res.json({ starred: false })
        } else {
            // add star
            starredPost = await stars.insert({ post: req.params.id, user: user.name })
            res.json({ starred: true })
        }
    }
})

app.options('/api/starred', cors(corsOptions)) // enable pre-flight request for starred post list

app.get('/api/starred', cors(corsOptions), async (req, res) => {  // returns list of starred posts
    if (typeof req.headers.authorization !== 'string') {
        res.json({ error: 'you need auth' })
    } else {
        const session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        const user = await getUserData(session.name)
        if (typeof user === 'undefined') {
            return res.json({ error: 'invalid auth no user found' })
        }
        const page = parseInt(req.query.page) || 0;

        let starredPosts = await stars.find({ user: user.name }, { sort: { _id: -1 }, limit: 15, skip: page * 15 })
        const ids = starredPosts.map(data => data.post)

        let postsToReturn = []
        let requests = ids.map(id => {
            //create a promise for each API call
            return new Promise((resolve, reject) => {
                fetch(`https://scratchdb.lefty.one/v3/forum/post/info/${id}`)
                    .then(response => response.json())
                    .then(data => resolve(data))
            })
        })
        Promise.all(requests).then((responses) => {
            //this gets called when all the promises have resolved/rejected.
            responses.forEach(response => {
                if (response) postsToReturn.push(response)
            })
            res.json(postsToReturn)
        }).catch(err => console.log(err))
    }
})

app.get('/api/reactions/:id', cors(), async (req, res) => { // returns all of the reactions for a post
    const postReactions = await getPostReactions(req.params.id)
    res.json(postReactions)
})

app.options('/api/reactions/:id', cors(corsOptions)) // enable pre-flight request for reacting to a post

app.post('/api/reactions/:id', cors(corsOptions), async (req, res) => { // reacts to a post, then returns new reaction list
    if (typeof req.headers.authorization !== 'string') {
        res.json({ error: 'you need auth' })
    } else {
        const session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        const user = await getUserData(session.name)
        if (typeof user === 'undefined') {
            return res.json({ error: 'invalid auth; no user found' })
        }
        let checkRes = await fetch(`https://scratch.mit.edu/discuss/post/${req.params.id}/source/`) // check if the post really exists
        if (!checkRes.ok) {
            return res.json({ error: 'post doesnt exist' })
        }
        if (!emojis.includes(req.body.emoji)) {
            let reactionWithEmoji = await reactions.findOne({ post: req.params.id, emoji: req.body.emoji }) // find a reaction with that emoji to check if thats a valid reaction option (its set by admin if invalid)

            if (!reactionWithEmoji && typeof user === 'undefined'.admin) return res.json({ error: 'invalid emoji' })
        }
        let postReaction = await reactions.findOne({ post: req.params.id, emoji: req.body.emoji, user: user.name })
        if (postReaction) {
            // remove reaction
            await reactions.remove(postReaction._id)
        } else {
            // add reaction
            await reactions.insert({ post: req.params.id, user: user.name, emoji: req.body.emoji })
        }
        // finally return all reactions
        let postReactions = await getPostReactions(req.params.id)
        res.json(postReactions)
    }
})

app.get('/auth/begin', (req, res) => {
    const redirectURL = `${req.protocol}://${req.get('host')}/auth/handle`;
    const encodedRedirectURL = Buffer.from(redirectURL).toString('base64');

    res.redirect(307,
        `https://auth.itinerary.eu.org/auth/?name=ocular&redirect=${encodedRedirectURL}`
    )
})

app.get('/auth/handle', async (req, res) => {
    // return res.send('ocular authentication is currently disabled due to an ocular authentication 0-day on the forums. we take security issues pretty seriously, so this functionality has been temporarily disabled until we can verify that any potential danger has been fixed. you can continue to use ocular logged out until then.')
    const redirectURL = `${req.protocol}://${req.get('host')}/auth/handle`; // cloudflare makes this work
    // the user is back from auth.
    const private = req.query.privateCode;
    let authResponse = await fetch(`https://auth.itinerary.eu.org/api/auth/verifyToken?privateCode=${encodeURIComponent(private)}`)
    let authData = await authResponse.json()
    if (authData.valid) {
        // get the proper case of the username instead of url case
        // ensure that redirect was either localhost:8081/auth/handle or my-ocular.jeffalo.net/auth/handle

        let redirect = authData.redirect

        if (redirect !== redirectURL) {
            return res.send('invalid redirect') // todo: frontend
        }

        let scratchResponse = await fetch(`https://api.scratch.mit.edu/users/${authData.username}/`, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0' // fake ua
            },
            method: 'GET'
        })
        let scratchData = await scratchResponse.json()

        if (!scratchData.username) {
            return res.json({ error: 'user not found on scratch' })
        }

        //TODO: don't assume the scratch user was found
        let foundUser = await getUserData(scratchData.username)

        if (!foundUser) {
            let now = new Date()
            foundUser = await users.insert({
                name: scratchData.username,
                status: '',
                color: null,
                meta: {
                    updated: now.toISOString(),
                    updatedBy: 'new user'
                }
            })
        }

        const token = await generateToken()
        const oneTimeToken = await generateToken() //
        addSession(token, scratchData.username, oneTimeToken)
        //console.log({ token, name: scratchData.username })
        res.redirect(`${frontendURL}/confirm-login?token=${oneTimeToken}`)
    } else {
        res.redirect(`${frontendURL}/login?error=${0}`) // failed fluffyscratch auth
        // res.json({ error: 'failed fluffyscratch auth' }) // commented out because showing users json for a common error isnt great. instead redirecting to the frontend where they can easily log in again is best
    }
})

app.get('/auth/info', cors(corsOptions), async (req, res) => {
    if (req.query.token) {
        const session = findSessionByOneTimeToken(req.query.token)
        if (session) {
            res.json({ name: session.name, token: session.token })
            await persistedSessions.update({ oneTimeToken: req.query.token }, { $set: { oneTimeToken: null } })
            session.oneTimeToken = null
        } else {
            res.json({ error: 'no session found. invalid or expired one time token' })
        }
    } else {
        res.json({ error: 'requires query parameter token' })
    }
})

app.post('/auth/remove', cors(corsOptions), async (req, res) => { // used when logging out or cancelling login. discards the session
    if (req.query.token) {
        const session = findSession(req.query.token)
        if (session) {
            let name = session.name
            removeSession(req.query.token)
            res.json({ ok: `removed session for ${name}` })
        } else {
            res.json({ error: 'the session from the token is already invalid/expired.' })
        }
    } else {
        res.json({ error: 'requires query parameter token' })
    }
})

app.options('/auth/me', cors(corsOptions)) // enable pre-flight request for getting user
app.get('/auth/me', cors(corsOptions), async (req, res) => {
    if (typeof req.headers.authorization !== 'string') {
        res.json({ error: 'you need auth' })
    } else {
        const session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        const user = await getUserData(session.name)
        user ? res.json(user) : res.json({ error: 'no user found.. this shouldn\'t happen' })
    }
})

app.get('/ban-info/:name', (req, res) => {
    // TODO: verify user is banned and perform some sort of authentication on this route to allow for ban message
    res.send('you\'ve been banned from ocular due to repeated misuse of the service. you can continue to use ocular logged out.')
})

// 404. catch all which redirects to frontend

app.use((req, res) => {
    res.redirect(`${frontendURL}${req.path}`)
})

function getUserData(name) {
    const regexName = '^' + escapeRegExp(name) + '$';
    return new Promise(async (resolve, reject) => {
        try {
            const user = await users.findOne({
                name: { $regex: new RegExp(regexName, 'i') }
            });
            resolve(user);
        } catch (error) {
            reject(new Error(error));
        }
    })
}

async function getPostReactions(id) {
    /* format:
    [
        {
            emoji: '😀',
            reactions: [
                (stuff from db, but really just needs username)
            ]
        },
        etc etc
    ]
    */
    return new Promise(async (resolve, reject) => {
        const postReactions = await reactions.find({ post: id })
        let grouped = []

        let postEmojis = [...emojis];

        postReactions.forEach(reaction => {
            if (!postEmojis.includes(reaction.emoji)) postEmojis.push(reaction.emoji)
        })

        postEmojis.forEach(emoji => {
            grouped.push({
                emoji, reactions: postReactions.filter(r => r.emoji == emoji)
            })
        })
        resolve(grouped)
    })
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
}

// const groupByKey = (list, key) => list.reduce((hash, obj) => ({ ...hash, [obj[key]]: (hash[obj[key]] || []).concat(obj) }), {})

// session management below

let sessions = [];

(async () => {
    sessions = await persistedSessions.find({})
})();

async function generateToken() {
    const buffer = await new Promise((resolve, reject) => {
        crypto.randomBytes(256, function (ex, buffer) {
            if (ex) {
                reject('error generating token');
            }
            resolve(buffer);
        });
    });
    const token = crypto
        .createHash('sha1')
        .update(buffer)
        .digest('hex');

    return token;
}

async function addSession(token, name, oneTimeToken, time = false) {
    // defaults to 6 hours
    // one time token is used for the confirm login screen, this prevents someone from reading the url and logging in. i know its not a perfect solution but its the best i can do

    sessions.push({ name, token, oneTimeToken });
    await persistedSessions.insert({ name, token, oneTimeToken })

    if (time) { // i doubt any sessions will be set with a time, because auth isnt fun to do. sessions should last 'forever'
        setTimeout(() => {
            // remove token after time seconds
            removeSession(token);
        }, time);
    }
}

async function removeSession(token) {
    sessions = sessions.filter(obj => {
        return obj.token !== token;
    })
    await persistedSessions.remove({ token })
}

function findSession(token) {
    const session = sessions.find(f => f.token == token)
    return session
}

function findSessionByOneTimeToken(oneTimeToken) {
    const session = sessions.find(f => f.oneTimeToken == oneTimeToken)
    return session
}

app.listen(port, () => {
    console.log(`Listening at http://localhost:${port}`)
})
