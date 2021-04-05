# my-ocular
my-ocular is the backend for ocular. it handles custom statuses, post starring and reactions. it does NOT handle forum data. that's provided by [ScratchDB](https://scratchdb.lefty.one/)

it's up at [my-ocular.jeffalo.net](https://my-ocular.jeffalo.net)

it's a simple node app, but it requires a mongodb database

## environment variables
| name         | use                             | default               |
|--------------|---------------------------------|-----------------------|
| MONGO_URL    | the url that the database is at | localhost/my-ocular   |
| FRONTEND_URL | where ocular is                 | http://localhost:8000 |