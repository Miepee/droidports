#ifndef __OPENAL_BRIDGE_H__
#define __OPENAL_BRIDGE_H__

#define AL_BRIDGE \
    AL_DECL_FWD_NR(alDopplerFactor,                void,        (ALfloat value),                                                                                                              (value)) \
    AL_DECL_FWD_NR(alDopplerVelocity,              void,        (ALfloat value),                                                                                                              (value)) \
    AL_DECL_FWD_NR(alSpeedOfSound,                 void,        (ALfloat value),                                                                                                              (value)) \
    AL_DECL_FWD_NR(alDistanceModel,                void,        (ALenum distanceModel),                                                                                                       (distanceModel)) \
    AL_DECL_FWD_NR(alEnable,                       void,        (ALenum capability),                                                                                                          (capability)) \
    AL_DECL_FWD_NR(alDisable,                      void,        (ALenum capability),                                                                                                          (capability)) \
    AL_DECL_FWD_NR(alGetBooleanv,                  void,        (ALenum param, ALboolean *values),                                                                                            (param, values)) \
    AL_DECL_FWD_NR(alGetIntegerv,                  void,        (ALenum param, ALint *values),                                                                                                (param, values)) \
    AL_DECL_FWD_NR(alGetFloatv,                    void,        (ALenum param, ALfloat *values),                                                                                              (param, values)) \
    AL_DECL_FWD_NR(alGetDoublev,                   void,        (ALenum param, ALdouble *values),                                                                                             (param, values)) \
    AL_DECL_FWD_NR(alListenerf,                    void,        (ALenum param, ALfloat value),                                                                                                (param, value)) \
    AL_DECL_FWD_NR(alListener3f,                   void,        (ALenum param, ALfloat value1, ALfloat value2, ALfloat value3),                                                               (param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alListenerfv,                   void,        (ALenum param, const ALfloat *values),                                                                                        (param, values)) \
    AL_DECL_FWD_NR(alListeneri,                    void,        (ALenum param, ALint value),                                                                                                  (param, value)) \
    AL_DECL_FWD_NR(alListener3i,                   void,        (ALenum param, ALint value1, ALint value2, ALint value3),                                                                     (param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alListeneriv,                   void,        (ALenum param, const ALint *values),                                                                                          (param, values)) \
    AL_DECL_FWD_NR(alGetListenerf,                 void,        (ALenum param, ALfloat *value),                                                                                               (param, value)) \
    AL_DECL_FWD_NR(alGetListener3f,                void,        (ALenum param, ALfloat *value1, ALfloat *value2, ALfloat *value3),                                                            (param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alGetListenerfv,                void,        (ALenum param, ALfloat *values),                                                                                              (param, values)) \
    AL_DECL_FWD_NR(alGetListeneri,                 void,        (ALenum param, ALint *value),                                                                                                 (param, value)) \
    AL_DECL_FWD_NR(alGetListener3i,                void,        (ALenum param, ALint *value1, ALint *value2, ALint *value3),                                                                  (param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alGetListeneriv,                void,        (ALenum param, ALint *values),                                                                                                (param, values)) \
    AL_DECL_FWD_NR(alGenSources,                   void,        (ALsizei n, ALuint *sources),                                                                                                 (n, sources)) \
    AL_DECL_FWD_NR(alDeleteSources,                void,        (ALsizei n, const ALuint *sources),                                                                                           (n, sources)) \
    AL_DECL_FWD_NR(alSourcef,                      void,        (ALuint source, ALenum param, ALfloat value),                                                                                 (source, param, value)) \
    AL_DECL_FWD_NR(alSource3f,                     void,        (ALuint source, ALenum param, ALfloat value1, ALfloat value2, ALfloat value3),                                                (source, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alSourcefv,                     void,        (ALuint source, ALenum param, const ALfloat *values),                                                                         (source, param, values)) \
    AL_DECL_FWD_NR(alSourcei,                      void,        (ALuint source, ALenum param, ALint value),                                                                                   (source, param, value)) \
    AL_DECL_FWD_NR(alSource3i,                     void,        (ALuint source, ALenum param, ALint value1, ALint value2, ALint value3),                                                      (source, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alSourceiv,                     void,        (ALuint source, ALenum param, const ALint *values),                                                                           (source, param, values)) \
    AL_DECL_FWD_NR(alGetSourcef,                   void,        (ALuint source, ALenum param, ALfloat *value),                                                                                (source, param, value)) \
    AL_DECL_FWD_NR(alGetSource3f,                  void,        (ALuint source, ALenum param, ALfloat *value1, ALfloat *value2, ALfloat *value3),                                             (source, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alGetSourcefv,                  void,        (ALuint source, ALenum param, ALfloat *values),                                                                               (source, param, values)) \
    AL_DECL_FWD_NR(alGetSourcei,                   void,        (ALuint source, ALenum param, ALint *value),                                                                                  (source, param, value)) \
    AL_DECL_FWD_NR(alGetSource3i,                  void,        (ALuint source, ALenum param, ALint *value1, ALint *value2, ALint *value3),                                                   (source, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alGetSourceiv,                  void,        (ALuint source, ALenum param, ALint *values),                                                                                 (source, param, values)) \
    AL_DECL_FWD_NR(alSourcePlayv,                  void,        (ALsizei n, const ALuint *sources),                                                                                           (n, sources)) \
    AL_DECL_FWD_NR(alSourceStopv,                  void,        (ALsizei n, const ALuint *sources),                                                                                           (n, sources)) \
    AL_DECL_FWD_NR(alSourceRewindv,                void,        (ALsizei n, const ALuint *sources),                                                                                           (n, sources)) \
    AL_DECL_FWD_NR(alSourcePausev,                 void,        (ALsizei n, const ALuint *sources),                                                                                           (n, sources)) \
    AL_DECL_FWD_NR(alSourcePlay,                   void,        (ALuint source),                                                                                                              (source)) \
    AL_DECL_FWD_NR(alSourceStop,                   void,        (ALuint source),                                                                                                              (source)) \
    AL_DECL_FWD_NR(alSourceRewind,                 void,        (ALuint source),                                                                                                              (source)) \
    AL_DECL_FWD_NR(alSourcePause,                  void,        (ALuint source),                                                                                                              (source)) \
    AL_DECL_FWD_NR(alSourceQueueBuffers,           void,        (ALuint source, ALsizei nb, const ALuint *buffers),                                                                           (source, nb, buffers)) \
    AL_DECL_FWD_NR(alSourceUnqueueBuffers,         void,        (ALuint source, ALsizei nb, ALuint *buffers),                                                                                 (source, nb, buffers)) \
    AL_DECL_FWD_NR(alGenBuffers,                   void,        (ALsizei n, ALuint *buffers),                                                                                                 (n, buffers)) \
    AL_DECL_FWD_NR(alDeleteBuffers,                void,        (ALsizei n, const ALuint *buffers),                                                                                           (n, buffers)) \
    AL_DECL_FWD_NR(alBufferData,                   void,        (ALuint buffer, ALenum format, const ALvoid *data, ALsizei size, ALsizei freq),                                               (buffer, format, data, size, freq)) \
    AL_DECL_FWD_NR(alBufferf,                      void,        (ALuint buffer, ALenum param, ALfloat value),                                                                                 (buffer, param, value)) \
    AL_DECL_FWD_NR(alBuffer3f,                     void,        (ALuint buffer, ALenum param, ALfloat value1, ALfloat value2, ALfloat value3),                                                (buffer, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alBufferfv,                     void,        (ALuint buffer, ALenum param, const ALfloat *values),                                                                         (buffer, param, values)) \
    AL_DECL_FWD_NR(alBufferi,                      void,        (ALuint buffer, ALenum param, ALint value),                                                                                   (buffer, param, value)) \
    AL_DECL_FWD_NR(alBuffer3i,                     void,        (ALuint buffer, ALenum param, ALint value1, ALint value2, ALint value3),                                                      (buffer, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alBufferiv,                     void,        (ALuint buffer, ALenum param, const ALint *values),                                                                           (buffer, param, values)) \
    AL_DECL_FWD_NR(alGetBufferf,                   void,        (ALuint buffer, ALenum param, ALfloat *value),                                                                                (buffer, param, value)) \
    AL_DECL_FWD_NR(alGetBuffer3f,                  void,        (ALuint buffer, ALenum param, ALfloat *value1, ALfloat *value2, ALfloat *value3),                                             (buffer, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alGetBufferfv,                  void,        (ALuint buffer, ALenum param, ALfloat *values),                                                                               (buffer, param, values)) \
    AL_DECL_FWD_NR(alGetBufferi,                   void,        (ALuint buffer, ALenum param, ALint *value),                                                                                  (buffer, param, value)) \
    AL_DECL_FWD_NR(alGetBuffer3i,                  void,        (ALuint buffer, ALenum param, ALint *value1, ALint *value2, ALint *value3),                                                   (buffer, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alGetBufferiv,                  void,        (ALuint buffer, ALenum param, ALint *values),                                                                                 (buffer, param, values)) \
    AL_DECL_FWD_NR(alcProcessContext,              void,        (ALCcontext *context),                                                                                                        (context)) \
    AL_DECL_FWD_NR(alcSuspendContext,              void,        (ALCcontext *context),                                                                                                        (context)) \
    AL_DECL_FWD_NR(alcDestroyContext,              void,        (ALCcontext *context),                                                                                                        (context)) \
    AL_DECL_FWD_NR(alcGetIntegerv,                 void,        (ALCdevice *device, ALCenum param, ALCsizei size, ALCint *values),                                                            (device, param, size, values)) \
    AL_DECL_FWD_NR(alcCaptureStart,                void,        (ALCdevice *device),                                                                                                          (device)) \
    AL_DECL_FWD_NR(alcCaptureStop,                 void,        (ALCdevice *device),                                                                                                          (device)) \
    AL_DECL_FWD_NR(alcCaptureSamples,              void,        (ALCdevice *device, ALCvoid *buffer, ALCsizei samples),                                                                       (device, buffer, samples)) \
    AL_DECL_FWD_NR(alBufferSubDataSOFT,            ALvoid,      (ALuint buffer,ALenum format,const ALvoid *data,ALsizei offset,ALsizei length),                                               (buffer,format,data,offset,length)) \
    /* AL_DECL_FWD_NR(alBufferDataStatic,             ALvoid,      (const ALint buffer, ALenum format, ALvoid *data, ALsizei len, ALsizei freq),                                                 (buffer, format, data, len, freq)) */\
    AL_DECL_FWD_NR(alGenEffects,                   ALvoid,      (ALsizei n, ALuint *effects),                                                                                                 (n, effects)) \
    AL_DECL_FWD_NR(alDeleteEffects,                ALvoid,      (ALsizei n, const ALuint *effects),                                                                                           (n, effects)) \
    AL_DECL_FWD_NR(alEffecti,                      ALvoid,      (ALuint effect, ALenum param, ALint iValue),                                                                                  (effect, param, iValue)) \
    AL_DECL_FWD_NR(alEffectiv,                     ALvoid,      (ALuint effect, ALenum param, const ALint *piValues),                                                                         (effect, param, piValues)) \
    AL_DECL_FWD_NR(alEffectf,                      ALvoid,      (ALuint effect, ALenum param, ALfloat flValue),                                                                               (effect, param, flValue)) \
    AL_DECL_FWD_NR(alEffectfv,                     ALvoid,      (ALuint effect, ALenum param, const ALfloat *pflValues),                                                                      (effect, param, pflValues)) \
    AL_DECL_FWD_NR(alGetEffecti,                   ALvoid,      (ALuint effect, ALenum param, ALint *piValue),                                                                                (effect, param, piValue)) \
    AL_DECL_FWD_NR(alGetEffectiv,                  ALvoid,      (ALuint effect, ALenum param, ALint *piValues),                                                                               (effect, param, piValues)) \
    AL_DECL_FWD_NR(alGetEffectf,                   ALvoid,      (ALuint effect, ALenum param, ALfloat *pflValue),                                                                             (effect, param, pflValue)) \
    AL_DECL_FWD_NR(alGetEffectfv,                  ALvoid,      (ALuint effect, ALenum param, ALfloat *pflValues),                                                                            (effect, param, pflValues)) \
    AL_DECL_FWD_NR(alGenFilters,                   ALvoid,      (ALsizei n, ALuint *filters),                                                                                                 (n, filters)) \
    AL_DECL_FWD_NR(alDeleteFilters,                ALvoid,      (ALsizei n, const ALuint *filters),                                                                                           (n, filters)) \
    AL_DECL_FWD_NR(alFilteri,                      ALvoid,      (ALuint filter, ALenum param, ALint iValue),                                                                                  (filter, param, iValue)) \
    AL_DECL_FWD_NR(alFilteriv,                     ALvoid,      (ALuint filter, ALenum param, const ALint *piValues),                                                                         (filter, param, piValues)) \
    AL_DECL_FWD_NR(alFilterf,                      ALvoid,      (ALuint filter, ALenum param, ALfloat flValue),                                                                               (filter, param, flValue)) \
    AL_DECL_FWD_NR(alFilterfv,                     ALvoid,      (ALuint filter, ALenum param, const ALfloat *pflValues),                                                                      (filter, param, pflValues)) \
    AL_DECL_FWD_NR(alGetFilteri,                   ALvoid,      (ALuint filter, ALenum param, ALint *piValue),                                                                                (filter, param, piValue)) \
    AL_DECL_FWD_NR(alGetFilteriv,                  ALvoid,      (ALuint filter, ALenum param, ALint *piValues),                                                                               (filter, param, piValues)) \
    AL_DECL_FWD_NR(alGetFilterf,                   ALvoid,      (ALuint filter, ALenum param, ALfloat *pflValue),                                                                             (filter, param, pflValue)) \
    AL_DECL_FWD_NR(alGetFilterfv,                  ALvoid,      (ALuint filter, ALenum param, ALfloat *pflValues),                                                                            (filter, param, pflValues)) \
    AL_DECL_FWD_NR(alGenAuxiliaryEffectSlots,      ALvoid,      (ALsizei n, ALuint *effectslots),                                                                                             (n, effectslots)) \
    AL_DECL_FWD_NR(alDeleteAuxiliaryEffectSlots,   ALvoid,      (ALsizei n, const ALuint *effectslots),                                                                                       (n, effectslots)) \
    AL_DECL_FWD_NR(alDeferUpdatesSOFT,             ALvoid,      (),                                                                                                                           ()) \
    AL_DECL_FWD_NR(alProcessUpdatesSOFT,           ALvoid,      (),                                                                                                                           ()) \
    AL_DECL_FWD_NR(alAuxiliaryEffectSloti,         ALvoid,      (ALuint effectslot, ALenum param, ALint iValue),                                                                              (effectslot, param, iValue)) \
    AL_DECL_FWD_NR(alAuxiliaryEffectSlotiv,        ALvoid,      (ALuint effectslot, ALenum param, const ALint *piValues),                                                                     (effectslot, param, piValues)) \
    AL_DECL_FWD_NR(alAuxiliaryEffectSlotf,         ALvoid,      (ALuint effectslot, ALenum param, ALfloat flValue),                                                                           (effectslot, param, flValue)) \
    AL_DECL_FWD_NR(alAuxiliaryEffectSlotfv,        ALvoid,      (ALuint effectslot, ALenum param, const ALfloat *pflValues),                                                                  (effectslot, param, pflValues)) \
    AL_DECL_FWD_NR(alGetAuxiliaryEffectSloti,      ALvoid,      (ALuint effectslot, ALenum param, ALint *piValue),                                                                            (effectslot, param, piValue)) \
    AL_DECL_FWD_NR(alGetAuxiliaryEffectSlotiv,     ALvoid,      (ALuint effectslot, ALenum param, ALint *piValues),                                                                           (effectslot, param, piValues)) \
    AL_DECL_FWD_NR(alGetAuxiliaryEffectSlotf,      ALvoid,      (ALuint effectslot, ALenum param, ALfloat *pflValue),                                                                         (effectslot, param, pflValue)) \
    AL_DECL_FWD_NR(alGetAuxiliaryEffectSlotfv,     ALvoid,      (ALuint effectslot, ALenum param, ALfloat *pflValues),                                                                        (effectslot, param, pflValues)) \
    /* AL_DECL_FWD_NR(alRequestFoldbackStart,         void,        (ALenum mode,ALsizei count,ALsizei length,ALfloat *mem,LPALFOLDBACKCALLBACK callback),                                        (mode,count,length,mem,callback)) */ \
    /* AL_DECL_FWD_NR(alRequestFoldbackStop,          void,        (),                                                                                                                           ()) */ \
    AL_DECL_FWD_NR(alBufferSamplesSOFT,            void,        (ALuint buffer, ALuint samplerate, ALenum internalformat, ALsizei samples, ALenum channels, ALenum type, const ALvoid *data), (buffer, samplerate, internalformat, samples, channels, type, data)) \
    AL_DECL_FWD_NR(alBufferSubSamplesSOFT,         void,        (ALuint buffer, ALsizei offset, ALsizei samples, ALenum channels, ALenum type, const ALvoid *data),                           (buffer, offset, samples, channels, type, data)) \
    AL_DECL_FWD_NR(alGetBufferSamplesSOFT,         void,        (ALuint buffer, ALsizei offset, ALsizei samples, ALenum channels, ALenum type, ALvoid *data),                                 (buffer, offset, samples, channels, type, data)) \
    AL_DECL_FWD_NR(alcRenderSamplesSOFT,           void,        (ALCdevice *device, ALCvoid *buffer, ALCsizei samples),                                                                       (device, buffer, samples)) \
    AL_DECL_FWD_NR(alSourcedSOFT,                  void,        (ALuint source, ALenum param, ALdouble value),                                                                                (source, param, value)) \
    AL_DECL_FWD_NR(alSource3dSOFT,                 void,        (ALuint source, ALenum param, ALdouble value1, ALdouble value2, ALdouble value3),                                             (source, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alSourcedvSOFT,                 void,        (ALuint source, ALenum param, const ALdouble *values),                                                                        (source, param, values)) \
    AL_DECL_FWD_NR(alGetSourcedSOFT,               void,        (ALuint source, ALenum param, ALdouble *value),                                                                               (source, param, value)) \
    AL_DECL_FWD_NR(alGetSource3dSOFT,              void,        (ALuint source, ALenum param, ALdouble *value1, ALdouble *value2, ALdouble *value3),                                          (source, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alGetSourcedvSOFT,              void,        (ALuint source, ALenum param, ALdouble *values),                                                                              (source, param, values)) \
    AL_DECL_FWD_NR(alSourcei64SOFT,                void,        (ALuint source, ALenum param, ALint64SOFT value),                                                                             (source, param, value)) \
    AL_DECL_FWD_NR(alSource3i64SOFT,               void,        (ALuint source, ALenum param, ALint64SOFT value1, ALint64SOFT value2, ALint64SOFT value3),                                    (source, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alSourcei64vSOFT,               void,        (ALuint source, ALenum param, const ALint64SOFT *values),                                                                     (source, param, values)) \
    AL_DECL_FWD_NR(alGetSourcei64SOFT,             void,        (ALuint source, ALenum param, ALint64SOFT *value),                                                                            (source, param, value)) \
    AL_DECL_FWD_NR(alGetSource3i64SOFT,            void,        (ALuint source, ALenum param, ALint64SOFT *value1, ALint64SOFT *value2, ALint64SOFT *value3),                                 (source, param, value1, value2, value3)) \
    AL_DECL_FWD_NR(alGetSourcei64vSOFT,            void,        (ALuint source, ALenum param, ALint64SOFT *values),                                                                           (source, param, values)) \
    AL_DECL_FWD_NR(alcDevicePauseSOFT,             void,        (ALCdevice *device),                                                                                                          (device)) \
    AL_DECL_FWD_NR(alcDeviceResumeSOFT,            void,        (ALCdevice *device),                                                                                                          (device)) \
    AL_DECL_FWD_NR(alcGetInteger64vSOFT,           void,        (ALCdevice *device, ALCenum pname, ALsizei size, ALCint64SOFT *values),                                                       (device, pname, size, values)) \
    AL_DECL_FWD   (alIsEnabled,                    ALboolean,   (ALenum capability),                                                                                                          (capability)) \
    AL_DECL_FWD   (alGetBoolean,                   ALboolean,   (ALenum param),                                                                                                               (param)) \
    AL_DECL_FWD   (alGetInteger,                   ALint,       (ALenum param),                                                                                                               (param)) \
    AL_DECL_FWD   (alGetFloat,                     ALfloat,     (ALenum param),                                                                                                               (param)) \
    AL_DECL_FWD   (alGetDouble,                    ALdouble,    (ALenum param),                                                                                                               (param)) \
    AL_DECL_FWD   (alGetError,                     ALenum,      (),                                                                                                                           ()) \
    AL_DECL_FWD   (alIsExtensionPresent,           ALboolean,   (const ALchar *extname),                                                                                                      (extname)) \
    AL_DECL_FWD   (alGetProcAddress,               void*,       (const ALchar *fname),                                                                                                        (fname)) \
    AL_DECL_FWD   (alGetEnumValue,                 ALenum,      (const ALchar *ename),                                                                                                        (ename)) \
    AL_DECL_FWD   (alIsSource,                     ALboolean,   (ALuint source),                                                                                                              (source)) \
    AL_DECL_FWD   (alIsBuffer,                     ALboolean,   (ALuint buffer),                                                                                                              (buffer)) \
    AL_DECL_FWD   (alcCreateContext,               ALCcontext*, (ALCdevice *device, const ALCint* attrlist),                                                                                  (device, attrlist)) \
    AL_DECL_FWD   (alcMakeContextCurrent,          ALCboolean,  (ALCcontext *context),                                                                                                        (context)) \
    AL_DECL_FWD   (alcGetCurrentContext,           ALCcontext*, (),                                                                                                                           ()) \
    AL_DECL_FWD   (alcGetContextsDevice,           ALCdevice*,  (ALCcontext *context),                                                                                                        (context)) \
    AL_DECL_FWD   (alcOpenDevice,                  ALCdevice*,  (const ALCchar *devicename),                                                                                                  (devicename)) \
    AL_DECL_FWD   (alcCloseDevice,                 ALCboolean,  (ALCdevice *device),                                                                                                          (device)) \
    AL_DECL_FWD   (alcGetError,                    ALCenum,     (ALCdevice *device),                                                                                                          (device)) \
    AL_DECL_FWD   (alcIsExtensionPresent,          ALCboolean,  (ALCdevice *device, const ALCchar *extname),                                                                                  (device, extname)) \
    AL_DECL_FWD   (alcGetProcAddress,              void*,       (ALCdevice *device, const ALCchar *funcname),                                                                                 (device, funcname)) \
    AL_DECL_FWD   (alcGetEnumValue,                ALCenum,     (ALCdevice *device, const ALCchar *enumname),                                                                                 (device, enumname)) \
    AL_DECL_FWD   (alcCaptureOpenDevice,           ALCdevice*,  (const ALCchar *devicename, ALCuint frequency, ALCenum format, ALCsizei buffersize),                                          (devicename, frequency, format, buffersize)) \
    AL_DECL_FWD   (alcCaptureCloseDevice,          ALCboolean,  (ALCdevice *device),                                                                                                          (device)) \
    AL_DECL_FWD   (alIsEffect,                     ALboolean,   (ALuint effect),                                                                                                              (effect)) \
    AL_DECL_FWD   (alIsFilter,                     ALboolean,   (ALuint filter),                                                                                                              (filter)) \
    AL_DECL_FWD   (alIsAuxiliaryEffectSlot,        ALboolean,   (ALuint effectslot),                                                                                                          (effectslot)) \
    AL_DECL_FWD   (alcSetThreadContext,            ALCboolean,  (ALCcontext *context),                                                                                                        (context)) \
    AL_DECL_FWD   (alcGetThreadContext,            ALCcontext*, (),                                                                                                                           ()) \
    AL_DECL_FWD   (alIsBufferFormatSupportedSOFT,  ALboolean,   (ALenum format),                                                                                                              (format)) \
    AL_DECL_FWD   (alcLoopbackOpenDeviceSOFT,      ALCdevice*,  (const ALCchar *deviceName),                                                                                                  (deviceName)) \
    AL_DECL_FWD   (alcIsRenderFormatSupportedSOFT, ALCboolean,  (ALCdevice *device, ALCsizei freq, ALCenum channels, ALCenum type),                                                           (device, freq, channels, type)) \
    AL_DECL_FWD   (alcResetDeviceSOFT,             ALCboolean,  (ALCdevice *device, const ALCint *attribs),                                                                                   (device, attribs))

#endif /* __OPENAL_BRIDGE_H__ */