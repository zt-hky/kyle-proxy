package telegram

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"globalprotect-manager/internal/vpn"
)

const (
	eventStreamIdleTimeout = 30 * time.Second
	eventStreamBotTimeout  = 5 * time.Second
	eventStreamMaxEvents   = 100
)

type eventStreams struct {
	service *Service

	mu          sync.Mutex
	streams     map[int64]*eventStream
	stopping    bool
	idleTimeout time.Duration
}

type eventStream struct {
	chatID     int64
	messageID  int
	events     []vpn.Event
	timer      *time.Timer
	generation uint64
}

func newEventStreams(service *Service) *eventStreams {
	return &eventStreams{
		service:     service,
		streams:     make(map[int64]*eventStream),
		idleTimeout: eventStreamIdleTimeout,
	}
}

func (e *eventStreams) push(ctx context.Context, chatID int64, event vpn.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return
	}

	stream := e.streams[chatID]
	if stream == nil {
		stream = &eventStream{chatID: chatID}
		e.streams[chatID] = stream
	}
	stream.events = append(stream.events, event)
	if len(stream.events) > eventStreamMaxEvents {
		copy(stream.events, stream.events[len(stream.events)-eventStreamMaxEvents:])
		clear(stream.events[eventStreamMaxEvents:])
		stream.events = stream.events[:eventStreamMaxEvents]
	}

	e.resetTimerLocked(stream)
	text := formatEvents(stream.events, false)
	if stream.messageID == 0 {
		message, err := e.service.bot.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID, Text: text, ParseMode: models.ParseModeHTML,
		})
		if err != nil || message == nil {
			log.Printf("telegram event stream send failed chat=%d error=%T", chatID, err)
			stream.timer.Stop()
			stream.timer = nil
			delete(e.streams, chatID)
			return
		}
		stream.messageID = message.ID
	} else {
		if _, err := e.service.bot.EditMessageText(ctx, &bot.EditMessageTextParams{
			ChatID: chatID, MessageID: stream.messageID, Text: text, ParseMode: models.ParseModeHTML,
		}); err != nil {
			log.Printf("telegram event stream edit failed chat=%d error=%T", chatID, err)
		}
	}
}

func (e *eventStreams) resetTimerLocked(stream *eventStream) {
	if stream.timer != nil {
		stream.timer.Stop()
	}
	stream.generation++
	generation := stream.generation
	stream.timer = time.AfterFunc(e.idleTimeout, func() {
		e.finalizeIdle(stream, generation)
	})
}

func (e *eventStreams) finalizeIdle(stream *eventStream, generation uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping || e.streams[stream.chatID] != stream || stream.generation != generation {
		return
	}
	delete(e.streams, stream.chatID)
	stream.timer = nil
	e.finalizeLocked(context.Background(), stream)
}

func (e *eventStreams) finalizeLocked(ctx context.Context, stream *eventStream) {
	callCtx, cancel := context.WithTimeout(ctx, eventStreamBotTimeout)
	defer cancel()
	if _, err := e.service.bot.EditMessageText(callCtx, &bot.EditMessageTextParams{
		ChatID: stream.chatID, MessageID: stream.messageID, Text: formatEvents(stream.events, true), ParseMode: models.ParseModeHTML,
	}); err != nil {
		log.Printf("telegram event stream final edit failed chat=%d error=%T", stream.chatID, err)
	}
}

func (e *eventStreams) shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return nil
	}
	e.stopping = true
	for _, stream := range e.streams {
		if stream.timer != nil {
			stream.timer.Stop()
			stream.timer = nil
		}
	}
	for chatID, stream := range e.streams {
		if err := ctx.Err(); err != nil {
			clear(e.streams)
			return err
		}
		e.finalizeLocked(ctx, stream)
		delete(e.streams, chatID)
	}
	return ctx.Err()
}
