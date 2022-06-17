# Simple Tweeter (Kaliaha Artsiom, s2110455009)

Das Ziel dieses Projekts bestand darin, eine einfache Version von Twitter nachzumachen.

Übersicht über die verwendeten Technologien:
- Programmiersprache: Golang
- Web Framework: Gin
- Bibliotheken:
    + gorilla mux (Routing)
    + chi (Routing)
    + uber zap (strukturiertes Logging)
    + viper (Konfigurationsmanagement)
    + gorm (ORM für Postgres)
    + gqlgen (Graphql Generator)
    + grpc & protobuf (RPC Calls)
    + service-engineering-go-lib (eine eigene Sammlung von Hilfsfunktionen)
    + jwt-go (Authentifizierung mittels JWT Tokens)
- Persistenz: MySQL (Userdaten), Postgres (Tweets)
- Deployment: mit Helm und ArgoCD auf einem lokalen Kubernetes Docker Desktop Cluster

### Architektur der Lösung

Die Architektur der Lösung besteht aus vier Services:
- Users Service: Registrierung der User, Ausstellung der JWT Tokens, Validierung der JWT Tokens. Dieser Service verwendet MySQL Datenbank.
- Tweets Service: Speicherung und Bereitstellung von Tweets. Tweets werden in der Postgres Datenbank gespeichert. Außerdem schreibt dieser Service Tweets in eine Kafka Queue, die dann vom Analytics Service konsumiert werden. 
- Graphql Service (a.k.a "Backend for Frontend" oder "API-Gateway"). Dieser Service leitet Daten an entsprechende Services weiter, liefert die Responses zurück, wandelt die Kommunikationsprotokolle um, um mit den entsprechenden Services kommunizieren zu können. 
- Analytics Service. Analytics Service arbeitet die Tweets aus der Kafka Queue ab und zählt die Anzahl der geposteten Tweets. Kommunikation mit diesem Service benötigt keine Authentifizierung. Der Service speichert keine Daten.

![1_architecture](/images/1_architecture.jpg)

### Kommunikation

Kommunikation erfolgt über folgende Schnittstellen:
- Users Service - Graphql Service: HTTP ist die einzige Schnittstelle
- Tweets Service - Graphql Service: gRPC als primärer Kommunikationskanal, HTTP als Fallback / sekundäre Schnittstelle.
- Tweets Service - Analytics Service: Messages werden vom Tweets Service über Kafka Queue an Analytics Service übertragen.

`Users Service - Graphql Service: gRPC`
```proto
syntax = "proto3";

option go_package = "github.com/stakkato95/twitter-service-users/protoservice";

package protoservice;

service UsersService {
    rpc CreateUser(User) returns (NewUser);

    rpc AuthUser(User) returns (Token);

    rpc AuthUserByToken(Token) returns (User);
}

message User {
    int64 id = 1;
    string username = 2;
    string password = 3;
}

message Token {
    string token = 1;
}

message NewUser {
    User user = 1;
	Token token = 2;
}
```

`Users Service - Graphql Service: HTTP`
| Method | Routes        | Description                                                     |
| ------ | ------------- | --------------------------------------------------------------- |
| POST   | /debug/create | Einen User im System registrieren                               |
| POST   | /debug/auth   | Einen JWT Token für einen registroerten User ausstellen         |

`Tweets Service - Graphql Service: HTTP`
| Method | Routes          | Description                                                     |
| ------ | --------------- | --------------------------------------------------------------- |
| POST   | /tweets         | Einen Tweet erstellen                                           |
| GET    | /tweets/:userId | Alle Tweets eines Users abfragen                                |

`Tweets Service - Analytics Service: "Tweets" Topic in Kafka`

`Analytics Service: HTTP (die für User gedachter Endpoint)`
| Method | Routes     | Description                                                     |
| ------ | ---------- | --------------------------------------------------------------- |
| GET    | /analytics | Anzahl der geposteten Tweets abfragen                           |



### Datenmodell

Daten werden von Tweets und Users Services in eigenen Datenbanken verwaltet.

![6_data_model](/images/6_data_model.jpg)

### Kurzer Überblick über Technologien

### service-engineering-go-lib

Das ist eine von mir geschriebene nano-Bibliothek, die die Funktionen / Komponenten umfasst, die in der letzten Übung einfach von einem zum anderen Service dupliziert wurden. Diese Komponenten sind Logging (Wrapper für uber zap Bibliothek), Konfigurationsmanagement (Wrapper für Viper Bibliothek) und eine Funktion, die in HTTP Handlers einer HTTP Response erleichtert. Link: https://github.com/stakkato95/service-engineering-go-lib

![2_go_lib](/images/2_go_lib.jpg)

### gin

![13_gin](/images/13_gin.jpg)

In Go Community ist Gin das beliebteste Framework. In Microservices, die mit Go entwickelt werden, werden oft einfach Routers eingesetzt, aber Gin bietet zusätzlich Parametervalidierung, Serving statischer Dateien und mehrere Arten von Middleware. In meinem Projekt wurde Gin nicht in allen Services eingesetzt, nur im Tweets Service (im Users Service wird "chi" Router verwendet).

```go
func Start() {
	repo := domain.NewTweetsRepo()
	service := service.NewTweetsService(repo)

	h := TweetsHandler{service}

	router := gin.Default()
	router.POST("/tweets", h.addTweet)
	router.GET("/tweets/:userId", h.getTweets)
	router.Run(config.AppConfig.ServerPort)
}

type TweetsHandler struct {
	service service.TweetsService
}

func (h *TweetsHandler) addTweet(ctx *gin.Context) {
	var tweetDto dto.TweetDto
	if err := ctx.ShouldBindJSON(&tweetDto); err != nil {
		errorResponse(ctx, err)
		return
	}

	createdTweet := h.service.AddTweet(tweetDto)
	ctx.JSON(http.StatusOK, dto.ResponseDto{Data: *createdTweet})
}
```

### gqlgen (Graphql Generator)

gqlgen ermöglicht Generierung eines Graphql Services auf Basis des Graphql Schemas. Graphql Schema meines Backend-for-Frontend Services schaut wie folgt aus:

```graphql
type Tweet {
  id: Int!
  userId: Int!
  text: String!
}

type Query {
  tweets: [Tweet!]!
}

input NewUser {
  username: String!
  password: String!
}

input Login {
  username: String!
  password: String!
}

input NewTweet {
  text: String!
}

type Mutation {
  createUser(input: NewUser!): String!

  login(input: Login!): String!

  createTweet(input: NewTweet!): Tweet!
}
```

Mit dem oben dargestellten Schema kann man folgende Queries ausführen:

```graphql
mutation {
  createUser(input: {username: "user1", password: "pass"})
}

mutation {
  login(input: {username: "user1", password: "pass"})
}

mutation {
  createTweet(input: {userId: 1, text: "new tweet"}) {
    id
    userId
    text
  }
}

{
  tweets {
    id
    userId
    text
  }
}
```

Go Handler-Funktionen, die aus dem Schema erzeugt wurden, schauen so aus:
```go
func (r *mutationResolver) CreateUser(ctx context.Context, input model.NewUser) (string, error) {
	return r.UserService.Create(input)
}

func (r *mutationResolver) Login(ctx context.Context, input model.Login) (string, error) {
	return r.UserService.Authenticate(input)
}

func (r *mutationResolver) CreateTweet(ctx context.Context, input model.NewTweet) (*model.Tweet, error) {
	user := middleware.ForContext(ctx)
	if user == nil {
		return nil, errors.New("invalid authorization")
	}

	return r.TweetService.CreateTweet(input, int(user.Id))
}

func (r *queryResolver) Tweets(ctx context.Context) ([]*model.Tweet, error) {
	user := middleware.ForContext(ctx)
	if user == nil {
		return nil, errors.New("invalid authorization")
	}

	return r.TweetService.GetTweets(int(user.Id))
}
```

### gorm

Im letzten Projekt (zu Message Oriented Middleware) wurden keine ORMs ausprobiert, die das Mapping von Entities auf Tabellen einer Datenbank ermöglichen. Einer der Gründe dafür war geringe beliebtheit von ORMs in Go Community. Viele Projekte verwenden einfach SQL Driver für entsprechende Datenbanken.

Dieses Mal wurde von mir eine der bekanntesten (und warscheinlich auch wenigen) ORM Bibliotheken ausprobiert, und zwar gorm. Gorm bietet alle gewöhnliche Funktionen eines ORMs, inklusive Migrationen, Select mit Where-Bediengungen, Updates usw.

```go
func NewTweetsRepo() TweetsRepo {
	db, err := gorm.Open(postgres.Open(config.AppConfig.DbSource), &gorm.Config{})
	db.AutoMigrate(&Tweet{})
	return &postgresTweetsRepo{db}
}

func (r *postgresTweetsRepo) AddTweet(tweet Tweet) *Tweet {
	r.db.Create(&tweet)
	return &tweet
}

func (r *postgresTweetsRepo) GetAllTweets(userId int) []Tweet {
	tweets := []Tweet{}
	r.db.Where("user_id = ?", userId).Find(&tweets)
	return tweets
}
```

### jwt-go

Diese Bibliothek bietet Heilfsfunktionen zur Erstellung und Validierung der JWT Tokens. Die Struktur eines Tokens im Falle meiner Anwendung schut so aus:

![7_jwt](/images/7_jwt.jpg)

Zusätzliche Hilfsfunktionen auf Basis jwt-go in meinem Projekt:

```go
var (
	SecretKey = []byte(config.AppConfig.JwtSecret)
)

func GenerateToken(username string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	tokenString, err := token.SignedString(SecretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ParseToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return SecretKey, nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username := claims["username"].(string)
		return username, nil
	} else {
		return "", err
	}
}
``` 

### Gorilla Mux
In Golang steht “mux” für “HTTP request multiplexer”. Solche Bibliotheken definieren, welche HTTP Endpoints von welchen Handlers bedient werden. Gorilla Mux bietet eine gute Leistung und Funktionalität im Vergleich mit anderen Multiplexern. Für Golang existiert eine Unmenge von Multiplexern, zumal sie die Entwicklung der Web-Services deutlich erleichtern.

```go
r := mux.NewRouter()
r.HandleFunc("/", handler)
r.HandleFunc("/products", handler).Methods("POST")
r.HandleFunc("/articles", handler).Methods("GET")
r.HandleFunc("/articles/{id}", handler).Methods("GET", "PUT")
r.HandleFunc("/authors", handler).Queries("surname", "{surname}")
```

### Uber Zap
Uber Zap bietet strukturiertes Logging. Unter strukturiertem Logging versteht man Logging in einem bestimmten Format, wie z.B. JSON. Dadurch kann das Parsen und die Verarbeitung von Logs deutlich vereinfacht werden. Zap ist eine der populärsten und die schnellste Implementierung des strukturierten Loggings für Golang.

```go
encoderConfig := zap.NewProductionEncoderConfig()
encoderConfig.TimeKey = "timestamp"
encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
encoderConfig.StacktraceKey = ""

config := zap.NewProductionConfig()
config.EncoderConfig = encoderConfig
```

```go
func Info(message string, fields ...zap.Field) {
	log.Info(message, fields...)
}
```
```json
{
    "level":"error",
    "timestamp":"2022-05-14T11:24:22.328Z",
    "caller":"domain/userProcessor.go:44",
    "msg":"error when reading a msg from kafka: write tcp 10.1.1.187:45268->10.1.1.149:9092: use of closed network connection"
}
```

### Viper
Viper ist eine Bibliothek für die Arbeit mit Konfigurationsdateien. Viper unterstützt unterschiedliche Dateiformate (JSON, TOML, YAML, HCL) und Konfigurationsquellen (Umgebungsvariablen, Command Line Flags, Remote Servers wie etcd, usw).

```go
type Config struct {
	ServerPort   string `mapstructure:"SERVER_PORT"`
	KafkaService string `mapstructure:"KAFKA_SERVICE"`
}

var AppConfig Config

func init() {
	viper.AddConfigPath(".")
	viper.SetConfigName("app")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		logger.Panic("config not found")
	}

	if err := viper.Unmarshal(&AppConfig); err != nil {
		logger.Panic("config can not be read")
	}

	if AppConfig == (Config{}) {
		logger.Panic("config is emtpy")
	}
}
```

```env
SERVER_PORT=:8080
KAFKA_SERVICE=kafka.default.svc.cluster.local:9092
```

### Istio
Istio ist eine auf Open Source basierende Service Mesh-Plattform, die steuert, wie Microservices Daten miteinander teilen. Das Produkt enthält APIs, über die Istio in beliebige Logging-Plattformen, Telemetrie- oder Richtliniensysteme integriert werden kann. Es ist für die Ausführung in den verschiedensten Umgebungen ausgelegt: On-Premise, Cloud, Kubernetes Container, Services auf virtuellen Maschinen und mehr.

In meinem Projekt wurde Istio zwecks Sammlung der Metriken und Verschlüsselung der Inter-Service-Kommunikation eingesetzt.

![14_istio_mesh_1](/images/14_istio_mesh_1.jpg)

![15_istio_mesh_2](/images/15_istio_mesh_2.jpg)

![16_istio_jaeger_1](/images/16_istio_jaeger_1.jpg)

![17_istio_jaeger_2](/images/17_istio_jaeger_2.jpg)

![18_istio_grafana](/images/18_istio_grafana.jpg)

### Packaging und Deployment

Als Packaging für den Service wurde Docker verwendet (Dockerfile im Rootverzeichnis jedes einzelnen Services). Build eines Images wird durch Makefile gestartet (auch wie im letzten Projekt). Jeder Service hat sein eigenes Repository auf Docker Hub.

![3_dockerhub](/images/3_dockerhub.jpg)

Für jeden Service wurde ein Helm Chart erstellt, der alle wichtigen Teile eines Kubernetes Microservices enthält, und zwar Deployment, Service und (wenn nötig) Ingress. Helm Charts liegen genau so wie Docker Images im Service Repository. Um alle Service auf einmal deployen zu können wurde ein so genannter Umbrella Chart erstellt. Dieser Chart liegt in einem eigenem Repository und beschreibt, wie alle Service deployt werden sollen. Dieser Chart ist auch fürs Deployment der Infrastruktur verantwrlich (Kafka, Postgres, MySQL). Dieser Umbrealla Chart und die entsprechende `values.yaml` Datei haben folgende Struktur:

`Chart.yaml des Umbrella Charts`
```yaml
apiVersion: v2
name: twitter-app
version: 0.1.12
dependencies:
  - name: twitter-graphql
    repository: https://stakkato95.github.io/twitter-graphql
    version: 0.1.2
  - name: twitter-users
    repository: https://stakkato95.github.io/twitter-users
    version: 0.1.1
  - name: twitter-tweets
    repository: https://stakkato95.github.io/twitter-tweets
    version: 0.1.1
  - name: twitter-analytics
    repository: https://stakkato95.github.io/twitter-analytics
    version: 0.1.0
  - name: mysql
    repository: https://charts.bitnami.com/bitnami
    version: 9.1.7
  - name: postgresql
    repository: https://charts.bitnami.com/bitnami
    version: 11.6.5
  - name: kafka
    repository: https://charts.bitnami.com/bitnami
    version: 17.2.6
```

`values.yaml des Umbrella Charts`
```yaml
mysql:
  auth:
    rootPassword: root
    database: users

global:
  postgresql:
    auth:
      username: root
      password: root
      database: tweetsdb

kafka:
  deleteTopicEnable: true
  auth:
    clientProtocol: plaintext
    sasl:
      jaas:
        clientUsers: "{user}"
        clientPasswords: "{user}"
```

Die ganze Microservice Anwendung wird mittels ArgoCD installiert. ArgoCD ist ein Open Source Projekt, das GitOps Modell des Deployments implementiert. Laut diesem Modell werden Microservices von einer Software-Komponente in einem Kubernetes Cluster installiert, die ebenfalls in einem (möglicherweise im selben) Kubernetes Cluster läuft. Diese Komponente (ArgoCD) beobachtet Repository, in dem ein Helm Umbrella-Chart gespeichrt ist, und installiert ihn auf dem Kubernetes Cluster jedes Mal, wenn er sich ändert. Dabei werden nicht alle Services auf einmal ersetzt / aktualisiert, sondern nur die Services, deren Definition sich im `Chart.yaml` des Umbrella-Charts geändert hat. 

Skripts zur Installation von ArgoCD auf einem lokalen Cluster wurden im `twitter-argo` Repository gespeichert. Das Deployment von Simple-Twitter mittels Argo schaut so aus:

![19_argo_1](/images/19_argo_1.jpg)

![20_argo_2](/images/20_argo_2.jpg)

![21_argo_3](/images/21_argo_3.jpg)

![22_argo_4](/images/22_argo_4.jpg)

Ein Umbrella Chart besteht aus mehreren untergeordneten Charts, die (auch wie der Umbrella Chart selbst) in Form eines Archivs auf einem Server zugänglich sein sollen. Der Prozess der Erstellung solcher Archive wurde mittels GitHub Actions automatisiert. Bei jedem Push auf Main branch wird eine neue Version des Charts erzeugt. Folglich wurde die Entwicklung einzelner Features auf Feature-Branches umgelegt.

![23_github_1](/images/23_github_1.jpg)

![24_github_2](/images/24_github_2.jpg)

Ein Beispiel der `index.yaml` Datei, die Versionen des Umbrella Charts enthält.
```yaml
apiVersion: v1
entries:
  twitter-app:
  - apiVersion: v2
    created: "2022-06-12T08:16:21.537501856Z"
    dependencies:
    - name: twitter-graphql
      repository: https://stakkato95.github.io/twitter-graphql
      version: 0.1.2
    - name: twitter-users
      repository: https://stakkato95.github.io/twitter-users
      version: 0.1.1
    - name: twitter-tweets
      repository: https://stakkato95.github.io/twitter-tweets
      version: 0.1.1
    - name: twitter-analytics
      repository: https://stakkato95.github.io/twitter-analytics
      version: 0.1.0
    - name: mysql
      repository: https://charts.bitnami.com/bitnami
      version: 9.1.7
    - name: postgresql
      repository: https://charts.bitnami.com/bitnami
      version: 11.6.5
    - name: kafka
      repository: https://charts.bitnami.com/bitnami
      version: 17.2.6
    digest: 01c0e22a9ef0d94964b2ca159d4c9500742dba9e3afd3f07cb8e5171a4844280
    name: twitter-app
    urls:
    - https://github.com/stakkato95/twitter-helm/releases/download/twitter-app-0.1.12/twitter-app-0.1.12.tgz
```

Ein Beispiel der `index.yaml` Datei, die Versionen des Graphql Charts enthält.

```yaml
apiVersion: v1
entries:
  twitter-graphql:
  - apiVersion: v2
    appVersion: 0.1.0
    created: "2022-06-11T20:22:53.621197402Z"
    description: A Helm chart for twitter graphql service
    digest: b130b31278434b5c6e60bea1623d6e5ccabbebb053e275bcf238e750fd94c435
    home: https://github.com/stakkato95/service-engineering-simple-twitter
    maintainers:
    - email: stakkato95@gmail.com
      name: Artsiom Kaliaha
    name: twitter-graphql
    type: application
    urls:
    - https://github.com/stakkato95/twitter-graphql/releases/download/twitter-graphql-0.1.2/twitter-graphql-0.1.2.tgz
    version: 0.1.2
```

`ci.yaml` Datei in `.github/workflows`, welche die Erstellung und die Veröffentlichung eines Charts auf GitHub automatisiert.
```yaml
name: Release Charts

on:
  push:
    branches:
      - main

jobs:
  release:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
        with:
          fetch-depth: 0

      - name: Configure Git
        run: |
          git config user.name "$GITHUB_ACTOR"
          git config user.email "$GITHUB_ACTOR@users.noreply.github.com"
      - name: Install Helm
        uses: azure/setup-helm@v1
        with:
          version: v3.8.1

      - name: Run chart-releaser
        uses: helm/chart-releaser-action@v1.4.0
        with:
          charts_dir: .
        env:
          CR_TOKEN: "${{ secrets.CR_TOKEN }}"
```

![25_github_3](/images/25_github_3.jpg)


### Testdurchlauf

Als Frontend für mein Projekt wird GraphiQL verwendet. 

Im ersten Schritt muss sich ein User im System anmelden. Das erfolgt mittels einer GraphQL Mutation Operation. Als Ergebniss bekommt man JWT Token. JWT Token muss man bei der Erstellung neuer Tweets oder beim Abfragen aller Tweets im Header mitgeben. In der Auth-Middleware wird der Token extrahiert und an Users Service geschickt, wo die Validierung erfolgt. GraphQL Service kriegt nur das Resultat der Validierung zurück (User oder Fehler Objekt). 

![8_create_user](/images/8_create_user.jpg)

Beim Verlust des Tokens kann ein neuer durch die Login-Operation ausgestellt werden.  

![9_login](/images/9_login.jpg)

Nach der Anmeldung kann ein User anfangen, Tweets zu posten. Dafür wird nur der Text des Tweets und der JWT Token im Auth-Header benötigt.

![10_create_tweet](/images/10_create_tweet.jpg)

Wenn keiner / falscher / ungültiger Token mitgegeben wird, bekommt User eine Fehlermeldung.

![11_auth_err](/images/11_auth_err.jpg)

Nach dem einige Tweets gepostet sind, können sie mittels einer Query abgefragt werden (dafür wird auch ein Token benötigt).

![12_all_tweets](/images/12_all_tweets.jpg)

### Con­clu­sio

Im vorliegenden Projekt wurde Folgendes ausprobiert:
- Message Oriented Middleware in Form von Kafka
- Graphql als "Frontend for Backend" Pattern
- gRPC für Inter-Service-Kommunikation
- Deployment von Microservices auf Basis Kubernetes mit Helm
- Automatisierung des Deployment Prozesses durch GitHub Actions und ArgoCD
- Authentifizierung mittels JWT beim Graphql Server
- Go und mehrere Go Bibliotheken und Frameworks für die Entwicklung von Microservices
- Erstellung eigener Go Packages am Beispiel service-engineering-go-lib