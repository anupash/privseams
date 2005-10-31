#ifndef HIPD_H
#define HIPD_H

extern struct hip_nl_handle nl_khipd;
extern time_t load_time;

int hip_agent_is_alive();
int hip_agent_filter(struct hip_common *msg);


#endif /* HIPD_H */
