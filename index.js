require('dotenv').config()
const fetch = require('node-fetch')
const crypto = require('crypto')

const express = require('express');
const db = require('monk')(process.env.MONGO_URL || 'localhost/my-ocular')

const users = db.get('users')
const stars = db.get('stars')
const reactions = db.get('reactions')
const persistedSessions = db.get('sessions') // used to store user sessions. it gets updated in sync with the sesions array but it is only used to persist sessions over restarts. it is only read from when server starts,

users.createIndex('name', { unique: true })

const app = express()
const port = 8081

let cors = require('cors')


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
    // let userList = await users.find({}, { sort: { _id: -1 }, limit: 15, skip: page * 15 })
    if (!req.headers.authorization) {
        res.json({ error: 'you need auth' })
    } else {
        let session = findSession(req.headers.authorization)

        if (!session) {
            return res.json({ error: 'invalid auth' })
        }

        let sessionUser = await getUserData(session.name)

        if (!sessionUser.admin) {
            return res.json({ error: `only admins can get a list of users.` })
        }
        let userList = await users.find({}, { sort: { "meta.updated": -1, _id: -1 } }) // TODO: pagination (see above)
        res.json(userList)
    }
})

app.get('/api/user/:name', cors(), async (req, res) => {
    let noReplace = req.query.noReplace
    let user = await getUserData(req.params.name.replace('*', ''))
    let allUsers = await users.find()

    if (!noReplace && user) {
        user.status = user.status.replace(/(?<!\\){joke}/g, jokes[Math.floor(Math.random() * jokes.length)])
        user.status = user.status.replace(/\\({joke})/g, "$1")

        user.status = user.status.replace(/(?<!\\){online}/g, sessions.length)
        user.status = user.status.replace(/\\({online})/g, "$1")

        user.status = user.status.replace(/(?<!\\){total}/g, allUsers.length)
        user.status = user.status.replace(/\\({total})/g, "$1")

        if (user.status.match(/(?<!\\){count}/)) {
            let apiRes = await fetch(`https://scratchdb.lefty.one/v3/forum/user/info/${user.name}`)
            let data = await apiRes.json()
            

            try {
                user.status = user.status.replace(/(?<!\\){count}/g, data.counts.total.count)
                user.status = user.status.replace(/\\({count})/g, "$1")
            } catch(ex) {
                
            }
        }
    }

    user ? res.json(user) : res.json({ error: "no user found" })
})

app.options('/api/user/:name', cors(corsOptions)) // enable pre-flight request for updating user

app.put('/api/user/:name', cors(), async (req, res) => {
    if (!req.headers.authorization) {
        res.json({ error: 'you need auth' })
    } else {
        let session = findSession(req.headers.authorization)

        if (!session) {
            return res.json({ error: 'invalid auth' })
        }

        let sessionUser = await getUserData(session.name)

        if (session.name.toLowerCase() !== req.params.name.toLowerCase() && !sessionUser.admin) {
            return res.json({ error: `editing someone else's status i see.` })
        }

        let user = await getUserData(req.params.name)

        // temporary security fix
        // return res.json({ error: 'for security reasons ocular statuses can not be updated at this time. sorry for the inconvenience' })

        if (user) {
            if (user.banned) return res.json({ error: `you are banned from ocular. visit https://my-ocular.jeffalo.net/ban-info/${user.name} for more information.` })

            let now = new Date()
            await users.update({ name: user.name }, { $set: { status: req.body.status, color: req.body.color, "meta.updatedBy": sessionUser.name, "meta.updated": now.toISOString() } })
            res.json({ ok: 'user updated' })
        } else {
            // this is an admin trying to update the status of a non-existent user. we should create that user with the specified data.

            let scratchResponse = await fetch(`https://api.scratch.mit.edu/users/${req.params.name}/`) // get the proper case of the username instead of whatever admin inputted
            let scratchData = await scratchResponse.json()

            let now = new Date()

            await users.insert({
                name: scratchData.username,
                status: req.body.status,
                color: req.body.color,
                meta: {
                    updated: now.toISOString(),
                    updatedBy: session.name
                }
            })
            res.json({ ok: 'user added' })
        }
    }
})

app.get('/api/user/:user/picture', cors(), async (req, res) => {
    let scratchResponse = await fetch(`https://api.scratch.mit.edu/users/${req.params.user}/`)
    let scratchData = await scratchResponse.json()
    let pictureURL = 'https://cdn2.scratch.mit.edu/get_image/user/0_90x90.png'
    if (scratchData.profile) pictureURL = scratchData.profile.images['90x90']
    res.redirect(pictureURL)
})

app.options('/api/starred/:id', cors(corsOptions)) // enable pre-flight request for getting star data

app.get('/api/starred/:id', cors(corsOptions), async (req, res) => { // returns whether the logged in user starred a post
    if (!req.headers.authorization) {
        res.json({ error: 'you need auth' })
    } else {
        let session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        let user = await getUserData(session.name)
        if (!user) {
            return res.json({ error: 'invalid auth no user found' })
        }

        let starredPost = await stars.findOne({ post: req.params.id, user: user.name })
        // console.log({ starredPost, post: req.params.id, user: user.name})
        starredPost ? res.json({ starred: true }) : res.json({ starred: false })
    }
})

app.options('/api/star/:id', cors(corsOptions)) // enable pre-flight request starring post

app.post('/api/star/:id', cors(corsOptions), async (req, res) => { // stars a post
    if (!req.headers.authorization) {
        res.json({ error: 'you need auth' })
    } else {
        let session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        let user = await getUserData(session.name)
        if (!user) {
            return res.json({ error: 'invalid auth no user found' })
        }
        let starredPost = await stars.findOne({ post: req.params.id, user: user.name })
        if (starredPost) {
            // remove star
            await stars.remove(starredPost._id)
            res.json({ starred: false })
        } else {
            // add star
            let checkRes = await fetch(`https://scratch.mit.edu/discuss/post/${req.params.id}/source/`) // check if the post really exists
            if (!checkRes.ok) {
                return res.json({ error: 'post doesnt exist' })
            }
            starredPost = await stars.insert({ post: req.params.id, user: user.name })
            res.json({ starred: true })
        }
    }
})

app.options('/api/starred', cors(corsOptions)) // enable pre-flight request for starred post list

app.get('/api/starred', cors(corsOptions), async (req, res) => {  // returns list of starred posts
    if (!req.headers.authorization) {
        res.json({ error: 'you need auth' })
    } else {
        let session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        let user = await getUserData(session.name)
        if (!user) {
            return res.json({ error: 'invalid auth no user found' })
        }
        const page = parseInt(req.query.page) || 0;

        let starredPosts = await stars.find({ user: user.name }, { sort: { _id: -1 }, limit: 15, skip: page * 15 })
        let ids = starredPosts.map(data => data.post)

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
    let postReactions = await getPostReactions(req.params.id)
    res.json(postReactions)
})

app.options('/api/reactions/:id', cors(corsOptions)) // enable pre-flight request for reacting to a post

app.post('/api/reactions/:id', cors(corsOptions), async (req, res) => { // reacts to a post, then returns new reaction list
    if (!req.headers.authorization) {
        res.json({ error: 'you need auth' })
    } else {
        let session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        let user = await getUserData(session.name)
        if (!user) {
            return res.json({ error: 'invalid auth no user found' })
        }
        let checkRes = await fetch(`https://scratch.mit.edu/discuss/post/${req.params.id}/source/`) // check if the post really exists
        if (!checkRes.ok) {
            return res.json({ error: 'post doesnt exist' })
        }
        if (!emojis.includes(req.body.emoji)) {
            let reactionWithEmoji = await reactions.findOne({ post: req.params.id, emoji: req.body.emoji }) // find a reaction with that emoji to check if thats a valid reaction option (its set by admin if invalid)

            if(!reactionWithEmoji && !user.admin) return res.json({ error: 'invalid emoji' })
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
    if (req.get('host') == 'localhost:8081') {
        res.redirect(`https://fluffyscratch.hampton.pw/auth/getKeys/v2?redirect=bG9jYWxob3N0OjgwODEvYXV0aC9oYW5kbGU=`)
    } else {
        res.redirect(`https://fluffyscratch.hampton.pw/auth/getKeys/v2?redirect=bXktb2N1bGFyLmplZmZhbG8ubmV0L2F1dGgvaGFuZGxl`)
    }
})

app.get('/auth/handle', async (req, res) => {
    // the user is back from hampton's thing.
    const private = req.query.privateCode

    let authResponse = await fetch('http://fluffyscratch.hampton.pw/auth/verify/v2/' + private)
    let authData = await authResponse.json()

    if (authData.valid) {
        // get the proper case of the username instead of url case

        let scratchResponse = await fetch(`https://api.scratch.mit.edu/users/${authData.username}/`)
        let scratchData = await scratchResponse.json()

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
        let session = findSessionByOneTimeToken(req.query.token)
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
        let session = findSession(req.query.token)
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
    if (!req.headers.authorization) {
        res.json({ error: 'you need auth' })
    } else {
        let session = findSession(req.headers.authorization)
        if (!session) {
            return res.json({ error: 'invalid auth' })
        }
        let user = await getUserData(session.name)
        user ? res.json(user) : res.json({ error: "no user found.. this shouldn't happen" })
    }
})

app.get('/ban-info/:name', (req, res) => {
    res.redirect('https://www.youtube.com/watch?v=dQw4w9WgXcQ')
})

// 404. catch all which redirects to frontend

app.use((req, res, next) => {
    res.redirect(`${frontendURL}${req.path}`)
})

function getUserData(name) {
    var regexName = "^" + escapeRegExp(name) + "$";
    return new Promise(async (resolve, reject) => {
        try {
            var user = await users.findOne({
                name: { $regex: new RegExp(regexName, "i") }
            });
            resolve(user);
        } catch (error) {
            reject(Error(error));
        }
    })
}

async function getPostReactions(id) {
    /* format:
    [
        {
            emoji: "😀",
            reactions: [
                (stuff from db, but really just needs username)
            ]
        },
        etc etc
    ]
    */
    return new Promise(async (resolve, reject) => {
        let postReactions = await reactions.find({ post: id })
        let grouped = []

        let postEmojis = emojis.slice(); // .slice so the original cant be edited

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

const groupByKey = (list, key) => list.reduce((hash, obj) => ({ ...hash, [obj[key]]: (hash[obj[key]] || []).concat(obj) }), {})

// session management below

let sessions = [];

(async () => {
    sessions = await persistedSessions.find({})
})();

async function generateToken() {
    const buffer = await new Promise((resolve, reject) => {
        crypto.randomBytes(256, function (ex, buffer) {
            if (ex) {
                reject("error generating token");
            }
            resolve(buffer);
        });
    });
    const token = crypto
        .createHash("sha1")
        .update(buffer)
        .digest("hex");

    return token;
}

async function addSession(token, name, oneTimeToken, time = false) {
    // defaults to 6 hours
    // one time token is used for the confirm login screen, this prevents someone from reading the url and logging in. i know its not a perfect solution but its the best i can do

    sessions.push({ name, token, oneTimeToken });
    await persistedSessions.insert({ name, token, oneTimeToken })

    if (time) { // i doubt any sessions will be set with a time, because auth isnt fun to do. sessions should last "forever"
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
