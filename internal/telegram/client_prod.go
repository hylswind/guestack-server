//go:build !dev

package telegram

// ClientID is the production bot ID (BotFather "Client ID"), the required
// "aud". It is compiled in so that it is part of the measured image.
// guestackd refuses to start if it is 0.
const ClientID int64 = 9192647203
