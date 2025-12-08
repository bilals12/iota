package telemetry

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	ServiceName    = "iota"
	ServiceVersion = "0.1.0"
)

var tracer trace.Tracer

type Config struct {
	Enabled     bool
	Endpoint    string
	ServiceName string
	Environment string
	SampleRate  float64
}

func ConfigFromEnv() Config {
	cfg := Config{
		Enabled:     os.Getenv("OTEL_ENABLED") == "true",
		Endpoint:    os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		ServiceName: os.Getenv("OTEL_SERVICE_NAME"),
		Environment: os.Getenv("OTEL_ENVIRONMENT"),
		SampleRate:  1.0,
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = ServiceName
	}
	if cfg.Environment == "" {
		cfg.Environment = "development"
	}
	return cfg
}

func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if !cfg.Enabled {
		tracer = otel.Tracer(cfg.ServiceName)
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(ServiceVersion),
			attribute.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	opts := []otlptracegrpc.Option{}
	if cfg.Endpoint != "" {
		opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true" {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}

	sampler := sdktrace.AlwaysSample()
	if cfg.SampleRate < 1.0 {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRate)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer = tp.Tracer(cfg.ServiceName)

	return tp.Shutdown, nil
}

func Tracer() trace.Tracer {
	if tracer == nil {
		tracer = otel.Tracer(ServiceName)
	}
	return tracer
}

func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, opts...)
}

func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

func RecordError(ctx context.Context, err error) {
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.RecordError(err)
	}
}

func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}

func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

type TimedOperation struct {
	ctx       context.Context
	span      trace.Span
	startTime time.Time
}

func StartOperation(ctx context.Context, name string, attrs ...attribute.KeyValue) (*TimedOperation, context.Context) {
	ctx, span := StartSpan(ctx, name, trace.WithAttributes(attrs...))
	return &TimedOperation{
		ctx:       ctx,
		span:      span,
		startTime: time.Now(),
	}, ctx
}

func (t *TimedOperation) End(err error) {
	if err != nil {
		t.span.RecordError(err)
	}
	t.span.SetAttributes(
		attribute.Int64("duration_ms", time.Since(t.startTime).Milliseconds()),
	)
	t.span.End()
}

func (t *TimedOperation) SetAttributes(attrs ...attribute.KeyValue) {
	t.span.SetAttributes(attrs...)
}
