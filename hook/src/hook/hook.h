#ifndef CUSTOMSPOTIFY_HOOK_H
#define CUSTOMSPOTIFY_HOOK_H

class Hook {
public:
  void Startup(bool bIsRenderer);
  void Shutdown();
};

extern Hook* g_Hook;

#endif //CUSTOMSPOTIFY_HOOK_H
