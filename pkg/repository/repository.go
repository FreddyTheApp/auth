package repository

import (
	"context"
	"log"
	"time"

	"github.com/FreddyTheApp/auth/api/user"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserRepository struct {
	collection *mongo.Collection
}

func NewUserRepository(mongoUri, mongoDB string) *UserRepository {
	// Set client options
	clientOptions := options.Client().ApplyURI(mongoUri)

	// Connect to MongoDB
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		panic(err)
	}

	// Check the connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Ping(ctx, nil)
	if err != nil {
		panic(err)
	}

	collection := client.Database(mongoDB).Collection("users")

	repository := &UserRepository{
		collection: collection,
	}

	if err := repository.ensureIndexes(ctx); err != nil {
		log.Fatalf("Failed to ensure indexes: %v", err)
	}

	return repository
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	filter := bson.M{"email": email}

	var u user.User

	err := r.collection.FindOne(ctx, filter).Decode(&u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (r *UserRepository) Save(ctx context.Context, u *user.User) error {
	u.ID = primitive.NewObjectID().Hex()
	_, err := r.collection.InsertOne(ctx, u)
	return err
}

func (r *UserRepository) ensureIndexes(ctx context.Context) error {
	mods := mongo.IndexModel{
		Keys:    bson.M{"email": 1},              // index for `email` field
		Options: options.Index().SetUnique(true), // make it a unique index
	}
	_, err := r.collection.Indexes().CreateOne(ctx, mods)
	return err
}

func (r *UserRepository) SaveRefreshToken(ctx context.Context, email, token string) error {
	_, err := r.collection.UpdateOne(ctx, bson.M{"email": email}, bson.M{"$set": bson.M{"refreshToken": token}})
	return err
}

func (r *UserRepository) FindRefreshToken(ctx context.Context, email, token string) (*user.User, error) {
	var u user.User
	err := r.collection.FindOne(ctx, bson.M{"email": email, "refreshToken": token}).Decode(&u)
	return &u, err
}
