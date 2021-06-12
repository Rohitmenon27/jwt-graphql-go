package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/graphql-go/graphql"
	"github.com/mitchellh/mapstructure"
)

type Employee struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type EmpDetails struct {
	EmpId    string `json: "id"`
	EmpTitle string `json:"title"`
	Address  string `json:"address"`
}

var jwtSecret []byte = []byte("GraphQL")

var accounts []Employee = []Employee{
	Employee{
		Username: "Gordon",
		Password: "64382",
	},
	Employee{
		Username: "Nick",
		Password: "7845",
	},
}

var emp []EmpDetails = []EmpDetails{
	EmpDetails{
		EmpId:    "78",
		EmpTitle: "Software Engineer",
		Address:  "San Jose",
	},
}

var accountType *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Account",
	Fields: graphql.Fields{
		"username": &graphql.Field{
			Type: graphql.String,
		},
		"password": &graphql.Field{
			Type: graphql.String,
		},
	},
})

var empType *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "EmpDetails",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: graphql.String,
		},
		"title": &graphql.Field{
			Type: graphql.String,
		},
		"address": &graphql.Field{
			Type: graphql.String,

			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				_, err := ValidateJWT(params.Context.Value("token").(string))
				if err != nil {
					return nil, err
				}
				return params.Source.(EmpDetails).Address, nil
			},
		},
	},
})

func ValidateJWT(t string) (interface{}, error) {
	if t == "" {
		return nil, errors.New("Authorization Token")
	}
	token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Error of")
		}
		return jwtSecret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var decodeToken interface{}
		mapstructure.Decode(claims, &decodeToken)
		return decodeToken, nil
	} else {
		return nil, errors.New("Invalid Token")
	}
}

func MainToken(response http.ResponseWriter, request *http.Request) {
	var user Employee
	_ = json.NewDecoder(request.Body).Decode(&user)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"password": user.Password,
	})
	tokenString, error := token.SignedString(jwtSecret)
	if error != nil {
		fmt.Println(error)
	}
	response.Header().Set("Content-type", "application/json")
	response.Write([]byte(`{"token"` + tokenString + `"}`))
}

func main() {
	fmt.Println("Launching :8080...")
	rootQuery := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"account": &graphql.Field{
				Type: accountType,
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {
					account, err := ValidateJWT(params.Context.Value("token").(string))
					if err != nil {
						return nil, err
					}
					for _, accountnew := range accounts {
						if accountnew.Username == account.(Employee).Username {
							return accountnew, nil
						}
					}
					return &Employee{}, nil
				},
			},
			"EmployeeDetails": &graphql.Field{
				Type: graphql.NewList(empType),
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {
					return emp, nil
				},
			},
		},
	})
	schema, _ := graphql.NewSchema(graphql.SchemaConfig{
		Query: rootQuery,
	})
	http.HandleFunc("/graphql", func(response http.ResponseWriter, request *http.Request) {
		result := graphql.Do(graphql.Params{
			Schema:        schema,
			RequestString: request.URL.Query().Get("query"),
			Context:       context.WithValue(context.Background(), "token", request.URL.Query().Get("token")),
		})
		json.NewEncoder(response).Encode(result)
	})
	http.HandleFunc("/login", MainToken)
	http.ListenAndServe(":8080", nil)

}
