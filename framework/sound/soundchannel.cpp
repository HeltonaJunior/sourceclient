/*
 * Copyright (c) 2010-2017 OTClient <https://github.com/edubart/otclient>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifdef FW_SOUND

#include "soundchannel.h"
#include "streamsoundsource.h"
#include "soundmanager.h"
#include <algorithm>

SoundSourcePtr SoundChannel::play(const std::string& filename, float fadetime, float gain)
{
    if(!g_sounds.isAudioEnabled() || !m_enabled)
        return nullptr;

    if(m_currentSource)
        m_currentSource->stop();

    m_currentSource = g_sounds.play(filename, fadetime, m_gain*gain);
    // Garantir que o gain atual é aplicado corretamente se o canal estiver habilitado
    if(m_currentSource && m_enabled) {
        m_currentSource->setGain(m_gain*gain);
    }
    return m_currentSource;
}

SoundSourcePtr SoundChannel::playEffect(const std::string& filename, float fadetime, float gain)
{
    if(!g_sounds.isAudioEnabled() || !m_enabled)
        return nullptr;

    SoundSourcePtr effectSource = g_sounds.play(filename, fadetime, m_gain*gain);
    if(effectSource) {
        effectSource->setLooping(false);
    }
    return effectSource;
}

void SoundChannel::stop(float fadetime)
{
    m_queue.clear();

    if(m_currentSource) {
        if(fadetime > 0)
            m_currentSource->setFading(StreamSoundSource::FadingOff, fadetime);
        else {
            m_currentSource->stop();
            m_currentSource = nullptr;
        }
    }
}

void SoundChannel::pause()
{
    if(m_currentSource) {
        m_currentSource->pause();
    }
}

void SoundChannel::resume()
{
    if(m_currentSource) {
        m_currentSource->resume();
    }
}

void SoundChannel::enqueue(const std::string& filename, float fadetime, float gain)
{
    if(gain == 0)
        gain = 1.0f;
    m_queue.push_back(QueueEntry{g_sounds.resolveSoundFile(filename), fadetime, gain});
    //update();
}

void SoundChannel::update()
{
    if(m_currentSource && !m_currentSource->isPlaying())
        m_currentSource = nullptr;

    if(!m_currentSource && !m_queue.empty() && g_sounds.isAudioEnabled() && m_enabled) {
        QueueEntry entry = m_queue.front();
        m_queue.pop_front();
        play(entry.filename, entry.fadetime, entry.gain);
    }
}

void SoundChannel::setEnabled(bool enable)
{
    if(m_enabled == enable)
        return;

    if(enable) {
        m_enabled = true;
        // Quando reabilitar, aplicar o gain atual (que pode ser 0 se estiver mutado)
        if(m_currentSource)
            m_currentSource->setGain(m_gain);
        update();
    } else {
        m_enabled = false;
        // Quando desabilitar, não parar a música, apenas mutar
        if(m_currentSource) {
            m_currentSource->setGain(0.0f);
        }
    }
}

bool SoundChannel::isPlaying()
{
    if(!m_currentSource)
        return false;
    return m_currentSource->isPlaying() && !m_currentSource->isPaused();
}

bool SoundChannel::isPaused()
{
    if(!m_currentSource)
        return false;
    return m_currentSource->isPaused();
}

float SoundChannel::getPlaybackTime()
{
    if(!m_currentSource)
        return 0.0f;
    // Try accurate seconds if available
    StreamSoundSource* stream = dynamic_cast<StreamSoundSource*>(m_currentSource.get());
    if(stream)
        return static_cast<float>(stream->tellSeconds());
    return m_currentSource->getPlaybackTime();
}

void SoundChannel::setPlaybackTime(float seconds)
{
    if(m_currentSource) {
        // Prefer accurate seeking for streams
        StreamSoundSource* stream = dynamic_cast<StreamSoundSource*>(m_currentSource.get());
        if(stream) {
            stream->seekSeconds(seconds);
        } else {
            m_currentSource->setPlaybackTime(seconds);
        }
    }
}

void SoundChannel::setGain(float gain)
{
    // Limitar o gain para valores válidos (0.0 a 1.0)
    m_gain = std::max(0.0f, std::min(gain, 1.0f));
    
    // Apenas aplicar o gain se o canal estiver habilitado
    if(m_currentSource && m_enabled)
        m_currentSource->setGain(m_gain);
}

#endif