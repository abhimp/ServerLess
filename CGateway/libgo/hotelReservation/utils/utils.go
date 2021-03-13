package utils

import (
	"fmt"
	"time"
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// APIURL for AWS APIGateway
var APIURL = "http://localhost:9087/cgi-hotel-reservation-api/"

// MongoClient : Get MongoDB connection
func MongoClient() (*mongo.Client, error) {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb+srv://dhruv:dhruv@hotel-reservation-us-ea.awtbr.mongodb.net/"))
    if err != nil {
        fmt.Println(err)
    }
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
    err = client.Connect(ctx)
	return client, err
}