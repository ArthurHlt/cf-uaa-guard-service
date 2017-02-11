package main

import (
	"context"
	"net/http"
	"os"

	"code.cloudfoundry.org/lager"
	"github.com/kelseyhightower/envconfig"
	"github.com/pivotal-cf/brokerapi"
	"github.com/satori/go.uuid"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	ROOT_UUID = "7a3691df-4bba-4468-9cca-85f281143d3f"
)

type GuardBroker struct {
	RouteServiceURLs   []string `envconfig:"route_service_urls" required:"true"`
	BrokerUsername     string   `envconfig:"broker_username" required:"true"`
	BrokerName         string   `envconfig:"broker_name" required:"true"`
	InsecureSkipVerify bool     `envconfig:"insecure_skip_verify"`
	BrokerPassword     string   `envconfig:"broker_password" required:"true"`
	Port               string   `envconfig:"port" default:"3000"`
	Plans              []Plan
}
type Plan struct {
	ID          string
	Name        string
	Description string
	ProxyUrl    string
}

func (guardBroker *GuardBroker) Services(context.Context) []brokerapi.Service {
	brokerUuid := uuid.NewV3(uuid.FromStringOrNil(ROOT_UUID), guardBroker.BrokerName)
	servicePlans := make([]brokerapi.ServicePlan, 0)
	for _, plan := range guardBroker.Plans {
		servicePlans = append(servicePlans, brokerapi.ServicePlan{
			ID: plan.ID,
			Name: plan.Name,
			Description: plan.Description,
		})
	}
	return []brokerapi.Service{
		brokerapi.Service{
			ID:            brokerUuid.String(),
			Name:          guardBroker.BrokerName,
			Description:   "Protect applications with cloud foundry authentication in the routing path",
			Bindable:      true,
			Tags:          []string{"route-service", "uaa-auth"},
			PlanUpdatable: false,
			Requires:      []brokerapi.RequiredPermission{brokerapi.PermissionRouteForwarding},
			Plans: servicePlans,
		},
	}
}

func (guardBroker *GuardBroker) Provision(context context.Context, instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, error) {
	return brokerapi.ProvisionedServiceSpec{}, nil
}

func (guardBroker *GuardBroker) Deprovision(context context.Context, instanceID string, details brokerapi.DeprovisionDetails, asyncAllowed bool) (brokerapi.DeprovisionServiceSpec, error) {
	return brokerapi.DeprovisionServiceSpec{}, nil
}

func (guardBroker *GuardBroker) Bind(context context.Context, instanceID string, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, error) {
	plan := guardBroker.PlanFromId(details.PlanID)
	if plan.ID == "" {
		return brokerapi.Binding{}, errors.New("Plan doesn't exists.")
	}
	return brokerapi.Binding{
		Credentials:     "",
		RouteServiceURL: plan.ProxyUrl,
	}, nil
}

func (guardBroker *GuardBroker) Unbind(context context.Context, instanceID string, bindingID string, details brokerapi.UnbindDetails) error {
	return nil
}

func (guardBroker *GuardBroker) LastOperation(context context.Context, instanceID, operationData string) (brokerapi.LastOperation, error) {
	return brokerapi.LastOperation{}, nil
}

func (guardBroker *GuardBroker) Update(context context.Context, instanceID string, details brokerapi.UpdateDetails, asyncAllowed bool) (brokerapi.UpdateServiceSpec, error) {
	return brokerapi.UpdateServiceSpec{}, nil
}
func (guardBroker GuardBroker) PlanFromId(id string) Plan {
	for _, plan := range guardBroker.Plans {
		if plan.ID == id {
			return plan
		}
	}
	return Plan{}
}
func (guardBroker *GuardBroker) LoadPlans() error {
	plans := make([]Plan, 0)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: guardBroker.InsecureSkipVerify},
		Proxy: http.ProxyFromEnvironment,
	}
	client := &http.Client{Transport: tr}
	for _, proxyUrl := range guardBroker.RouteServiceURLs {
		var plan Plan
		resp, err := client.Get(proxyUrl + "/info")
		if err != nil {
			return errors.New(
				fmt.Sprintf(
					"Error when loading plan from '%s': %s",
					proxyUrl,
					err.Error(),
				),
			)
		}
		err = json.NewDecoder(resp.Body).Decode(&plan)
		if err != nil {
			return errors.New(
				fmt.Sprintf(
					"Error when decoding plan from '%s': %s",
					proxyUrl,
					err.Error(),
				),
			)
		}
		plan.ProxyUrl = proxyUrl
		planUuid := uuid.NewV3(uuid.FromStringOrNil(ROOT_UUID), plan.Name)
		plan.ID = planUuid.String()
		plans = append(plans, plan)
		resp.Body.Close()
	}
	guardBroker.Plans = plans
	return nil
}
func main() {
	serviceBroker := &GuardBroker{
		Plans: make([]Plan, 0),
	}
	logger := lager.NewLogger("guard-broker")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.DEBUG))
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.ERROR))
	err := envconfig.Process("guard", serviceBroker)
	if err != nil {
		logger.Error("env-parse", err)
	}
	err = serviceBroker.LoadPlans()
	if err != nil {
		logger.Error("env-parse", err)
	}
	credentials := brokerapi.BrokerCredentials{
		Username: serviceBroker.BrokerUsername,
		Password: serviceBroker.BrokerPassword,
	}

	brokerAPI := brokerapi.New(serviceBroker, logger, credentials)
	http.Handle("/", brokerAPI)

	http.ListenAndServe(":" + serviceBroker.Port, nil)
}
