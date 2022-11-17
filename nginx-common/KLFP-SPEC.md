# Setup File (`setp`)
## Main Block (`klpf`)
Children: [*Channel Block*](#channel-block-chnl)

### Block Header
- uint32_t **uncomp_size**
- uint32_t **version**
- uint32_t **type**
- uint64_t **created**

## Channel Block (`chnl`)
Parent: [*Main Block*](#main-block-klpf)

Children: [*Track Block*](#track-block-trak), [*Dynamic Var Block*](#dynamic-var-block-dynv), [*Filler Block*](#filler-block-fllr), [*Timeline Block*](#timeline-block-tmln), [*Variant Block*](#variant-block-vrnt)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *opaquep*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_live_persist_setup_channel_t *p*
    - uint64_t **uid**
    - uint32_t **version**
    - uint32_t **initial_segment_index**
    - uint32_t **segment_duration**
    - uint32_t **input_delay**
    - uint64_t **start_sec**
- struct ngx_str_t *opaque*
    - uint32_t **len**
    - u_char **data**[*len*]

## Track Block (`trak`)
Parent: [*Channel Block*](#channel-block-chnl)

Children: [*Media Info Setup Block*](#media-info-setup-block-misp)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_live_persist_setup_track_t *p*
    - uint32_t **track_id**
    - uint32_t **media_type**
    - uint32_t **type**
    - uint32_t **reserved**
    - uint64_t **start_sec**
- struct ngx_str_t *opaque*
    - uint32_t **len**
    - u_char **data**[*len*]

## Media Info Setup Block (`misp`)
Parent: [*Track Block*](#track-block-trak)

### Block Data
- struct ngx_str_t *group_id*
    - uint32_t **len**
    - u_char **data**[*len*]

## Dynamic Var Block (`dynv`)
Parent: [*Channel Block*](#channel-block-chnl)

### Block Data
- struct ngx_str_t *key*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *value*
    - uint32_t **len**
    - u_char **data**[*len*]

## Filler Block (`fllr`)
Parent: [*Channel Block*](#channel-block-chnl)

### Block Data
- struct ngx_str_t *channel_id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *preset_name*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *timeline_id*
    - uint32_t **len**
    - u_char **data**[*len*]
- uint32_t **filler_start_index**

## Timeline Block (`tmln`)
Parent: [*Channel Block*](#channel-block-chnl)

### Block Data
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_live_timeline_conf_t *conf*
    - int64_t **start**
    - int64_t **end**
    - int64_t **period_gap**
    - uint64_t **max_duration**
    - uint32_t **max_segments**
    - unsigned **active:1**
    - unsigned **no_truncate:1**
- struct ngx_live_timeline_manifest_conf_t *manifest_conf*
    - uint64_t **max_duration**
    - uint32_t **max_segments**
    - uint32_t **expiry_threshold**
    - uint32_t **target_duration_segments**
    - uint32_t **end_list**
- struct ngx_str_t *src_id*
    - uint32_t **len**
    - u_char **data**[*len*]

## Variant Block (`vrnt`)
Parent: [*Channel Block*](#channel-block-chnl)

### Block Data
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_live_persist_setup_variant_t *p*
    - uint32_t **role**
    - uint32_t **is_default**
    - uint32_t **track_count**
- struct ngx_str_t *label*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *lang*
    - uint32_t **len**
    - u_char **data**[*len*]
- uint32_t **track_id**[*p.track_count*]
- struct ngx_str_t *opaque*
    - uint32_t **len**
    - u_char **data**[*len*]

# Serve File (`serv`)
## Main Block (`klpf`)
Children: [*Channel Block*](#channel-block-chnl-1), [*Segment Block*](#segment-block-sgmt), [*Error Block*](#error-block-errr)

### Block Header
- uint32_t **uncomp_size**
- uint32_t **version**
- uint32_t **type**
- uint64_t **created**

## Channel Block (`chnl`)
Parent: [*Main Block*](#main-block-klpf-1)

Children: [*Timeline Block*](#timeline-block-tmln-1), [*Variant Block*](#variant-block-vrnt-1), [*Dynamic Var Block*](#dynamic-var-block-dynv-1), [*Segment Index Block*](#segment-index-block-sgix), [*Rendition Report Block*](#rendition-report-block-rrpt)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_ksmp_channel_header_t *p*
    - uint32_t **track_count**
    - uint32_t **variant_count**
    - uint32_t **timescale**
    - uint32_t **req_media_types**
    - uint32_t **res_media_types**
    - uint32_t **part_duration**
    - int64_t **last_modified**
    - int64_t **now**

## Timeline Block (`tmln`)
Parent: [*Channel Block*](#channel-block-chnl-1)

Children: [*Period Block*](#period-block-tprd)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_ksmp_timeline_header_t *p*
    - int64_t **availability_start_time**
    - uint32_t **period_count**
    - uint32_t **first_period_index**
    - int64_t **first_period_initial_time**
    - uint32_t **first_period_initial_segment_index**
    - uint32_t **sequence**
    - int64_t **last_modified**
    - uint32_t **target_duration**
    - uint32_t **end_list**
    - uint32_t **skipped_periods**
    - uint32_t **skipped_segments**
    - uint32_t **last_skipped_index**
    - uint32_t **reserved**

## Period Block (`tprd`)
Parent: [*Timeline Block*](#timeline-block-tmln-1)

### Block Header
- struct ngx_ksmp_period_header_t *p*
    - int64_t **time**
    - uint32_t **segment_index**
    - uint32_t **reserved**

### Block Data
- struct ngx_ksmp_segment_repeat_t *sd*[*max*]
    - uint32_t **count**
    - uint32_t **duration**

## Variant Block (`vrnt`)
Parent: [*Channel Block*](#channel-block-chnl-1)

Children: [*Track Block*](#track-block-trak-1)

### Block Data
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_ksmp_variant_t *p*
    - uint32_t **role**
    - uint32_t **is_default**
- struct ngx_str_t *label*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *lang*
    - uint32_t **len**
    - u_char **data**[*len*]
- uint32_t **track_id**[*p.track_count*]

## Track Block (`trak`)
Parent: [*Variant Block*](#variant-block-vrnt-1)

Children: [*Media Info Queue Block*](#media-info-queue-block-miqu), [*Track Parts Block*](#track-parts-block-tprt), [*Segment Info Block*](#segment-info-block-sgnf)

### Block Header
- struct ngx_ksmp_track_header_t *p*
    - uint32_t **id**
    - uint32_t **media_type**

## Media Info Queue Block (`miqu`)
Parent: [*Track Block*](#track-block-trak-1)

Children: [*Media Info Block*](#media-info-block-minf)

### Block Header
- struct ngx_ksmp_media_info_queue_header_t *p*
    - uint32_t **count**

## Media Info Block (`minf`)
Parent: [*Media Info Queue Block*](#media-info-queue-block-miqu)

### Block Header
- struct ngx_ksmp_media_info_header_t *p*
    - uint32_t **track_id**
    - uint32_t **segment_index**
    - struct ngx_ksmp_media_info_stats_t *stats*
        - uint64_t **bitrate_sum**
        - uint32_t **bitrate_count**
        - uint32_t **bitrate_max**
        - uint64_t **duration**
        - uint64_t **frame_count**
        - uint32_t **frame_rate_min**
        - uint32_t **frame_rate_max**
- struct kmp_media_info_t *kmp*
    - uint32_t **media_type**
    - uint32_t **codec_id**
    - uint32_t **timescale**
    - uint32_t **bitrate**
    - union kmp_media_info_union_t *u*
        - struct kmp_video_media_info_t *video*
            - uint16_t **width**
            - uint16_t **height**
            - struct kmp_rational_t *frame_rate*
                - uint32_t **num**
                - uint32_t **denom**
            - uint32_t **cea_captions**
        - struct kmp_audio_media_info_t *audio*
            - uint16_t **channels**
            - uint16_t **bits_per_sample**
            - uint32_t **sample_rate**
            - uint64_t **channel_layout**

### Block Data
- u_char **extra_data**[*max*]

## Track Parts Block (`tprt`)
Parent: [*Track Block*](#track-block-trak-1)

### Block Header
- struct ngx_ksmp_track_parts_header_t *header*
    - uint32_t **count**

## Segment Info Block (`sgnf`)
Parent: [*Track Block*](#track-block-trak-1)

### Block Data
- struct ngx_ksmp_segment_info_elt_t *info*[*max*]
    - uint32_t **index**
    - uint32_t **bitrate**

## Dynamic Var Block (`dynv`)
Parent: [*Channel Block*](#channel-block-chnl-1)

### Block Data
- struct ngx_str_t *key*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *value*
    - uint32_t **len**
    - u_char **data**[*len*]

## Segment Index Block (`sgix`)
Parent: [*Channel Block*](#channel-block-chnl-1)

### Block Data
- struct ngx_ksmp_segment_index_t *p*
    - uint32_t **index**
    - uint32_t **duration**
    - int64_t **start**
    - int64_t **time**
    - int64_t **correction**

## Rendition Report Block (`rrpt`)
Parent: [*Channel Block*](#channel-block-chnl-1)

### Block Header
- struct ngx_ksmp_rendition_reports_header_t *header*
    - uint32_t **count**

## Segment Block (`sgmt`)
Parent: [*Main Block*](#main-block-klpf-1)

Children: [*Frame List Block*](#frame-list-block-trun), [*Frame Data Block*](#frame-data-block-mdat), [*Segment Media Info Block*](#segment-media-info-block-sgmi)

### Block Header
- struct ngx_ksmp_segment_header_t *header*
    - uint32_t **track_id**
    - uint32_t **index**
    - uint32_t **frame_count**
    - uint32_t **part_sequence**
    - int64_t **start_dts**

## Frame List Block (`trun`)
Parent: [*Segment Block*](#segment-block-sgmt)

### Block Data
- struct ngx_ksmp_frame_t *frame*[*max*]
    - uint32_t **size**
    - uint32_t **key_frame**
    - uint32_t **duration**
    - uint32_t **pts_delay**

## Frame Data Block (`mdat`)
Parent: [*Segment Block*](#segment-block-sgmt)

### Block Data
- u_char **data**[*max*]

## Segment Media Info Block (`sgmi`)
Parent: [*Segment Block*](#segment-block-sgmt)

### Block Header
- struct kmp_media_info_t *kmp*
    - uint32_t **media_type**
    - uint32_t **codec_id**
    - uint32_t **timescale**
    - uint32_t **bitrate**
    - union kmp_media_info_union_t *u*
        - struct kmp_video_media_info_t *video*
            - uint16_t **width**
            - uint16_t **height**
            - struct kmp_rational_t *frame_rate*
                - uint32_t **num**
                - uint32_t **denom**
            - uint32_t **cea_captions**
        - struct kmp_audio_media_info_t *audio*
            - uint16_t **channels**
            - uint16_t **bits_per_sample**
            - uint32_t **sample_rate**
            - uint64_t **channel_layout**

### Block Data
- u_char **extra_data**[*max*]

## Error Block (`errr`)
Parent: [*Main Block*](#main-block-klpf-1)

### Block Data
- uint32_t **code**
- struct ngx_str_t *message*
    - uint32_t **len**
    - u_char **data**[*len*]

# Filler File (`fllr`)
## Main Block (`klpf`)
Children: [*Channel Block*](#channel-block-chnl-2)

### Block Header
- uint32_t **uncomp_size**
- uint32_t **version**
- uint32_t **type**
- uint64_t **created**

## Channel Block (`chnl`)
Parent: [*Main Block*](#main-block-klpf-2)

Children: [*Track Block*](#track-block-trak-2), [*Timeline Block*](#timeline-block-tmln-2)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *opaquep*
    - uint32_t **len**
    - u_char **data**[*len*]

## Track Block (`trak`)
Parent: [*Channel Block*](#channel-block-chnl-2)

Children: [*Segment Block*](#segment-block-sgmt-1), [*Media Info Block*](#media-info-block-minf-1)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- uint32_t **media_type**

## Segment Block (`sgmt`)
Parent: [*Track Block*](#track-block-trak-2)

Children: [*Frame List Block*](#frame-list-block-trun-1), [*Frame Data Block*](#frame-data-block-mdat-1)

### Block Header
- struct ngx_ksmp_segment_header_t *sp*
    - uint32_t **track_id**
    - uint32_t **index**
    - uint32_t **frame_count**
    - uint32_t **part_sequence**
    - int64_t **start_dts**

## Frame List Block (`trun`)
Parent: [*Segment Block*](#segment-block-sgmt-1)

### Block Data
- struct ngx_ksmp_frame_t *frame*[*max*]
    - uint32_t **size**
    - uint32_t **key_frame**
    - uint32_t **duration**
    - uint32_t **pts_delay**

## Frame Data Block (`mdat`)
Parent: [*Segment Block*](#segment-block-sgmt-1)

### Block Data
- u_char **data**[*max*]

## Media Info Block (`minf`)
Parent: [*Track Block*](#track-block-trak-2)

### Block Header
- struct kmp_media_info_t *kmp*
    - uint32_t **media_type**
    - uint32_t **codec_id**
    - uint32_t **timescale**
    - uint32_t **bitrate**
    - union kmp_media_info_union_t *u*
        - struct kmp_video_media_info_t *video*
            - uint16_t **width**
            - uint16_t **height**
            - struct kmp_rational_t *frame_rate*
                - uint32_t **num**
                - uint32_t **denom**
            - uint32_t **cea_captions**
        - struct kmp_audio_media_info_t *audio*
            - uint16_t **channels**
            - uint16_t **bits_per_sample**
            - uint32_t **sample_rate**
            - uint64_t **channel_layout**

### Block Data
- u_char **extra_data**[*max*]

## Timeline Block (`tmln`)
Parent: [*Channel Block*](#channel-block-chnl-2)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- int64_t **time**

### Block Data
- uint32_t **duration**[*max*]

# Index File (`sgix`)
## Main Block (`klpf`)
Children: [*Channel Block*](#channel-block-chnl-3)

### Block Header
- uint32_t **uncomp_size**
- uint32_t **version**
- uint32_t **type**
- uint64_t **created**

## Channel Block (`chnl`)
Parent: [*Main Block*](#main-block-klpf-3)

Children: [*Track Block*](#track-block-trak-3), [*Segment List Block*](#segment-list-block-slst), [*Timeline Block*](#timeline-block-tmln-3), [*Syncer Block*](#syncer-block-sync), [*Timeline Channel Block*](#timeline-channel-block-tlch), [*Variant Block*](#variant-block-vrnt-2)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *opaquep*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_live_persist_index_channel_t *p*
    - uint64_t **uid**
    - uint32_t **min_index**
    - uint32_t **max_index**
    - uint32_t **next_part_sequence**
    - uint32_t **last_segment_media_types**
    - int64_t **last_segment_created**
    - int64_t **last_modified**

## Track Block (`trak`)
Parent: [*Channel Block*](#channel-block-chnl-3)

Children: [*Media Info Queue Block*](#media-info-queue-block-miqu-1), [*Media Info Source Block*](#media-info-source-block-msrc), [*Segment Info Block*](#segment-info-block-sgnf-1), [*Syncer Track Block*](#syncer-track-block-synt)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_live_persist_index_track_t *p*
    - uint32_t **track_id**
    - uint32_t **has_last_segment**
    - uint32_t **last_segment_bitrate**
    - uint32_t **initial_segment_index**
    - int64_t **last_frame_pts**
    - int64_t **last_frame_dts**
    - uint64_t **next_frame_id**

## Media Info Queue Block (`miqu`)
Parent: [*Track Block*](#track-block-trak-3)

Children: [*Media Info Block*](#media-info-block-minf-2)

## Media Info Block (`minf`)
Parent: [*Media Info Queue Block*](#media-info-queue-block-miqu-1)

### Block Header
- struct ngx_ksmp_media_info_header_t *p*
    - uint32_t **track_id**
    - uint32_t **segment_index**
    - struct ngx_ksmp_media_info_stats_t *stats*
        - uint64_t **bitrate_sum**
        - uint32_t **bitrate_count**
        - uint32_t **bitrate_max**
        - uint64_t **duration**
        - uint64_t **frame_count**
        - uint32_t **frame_rate_min**
        - uint32_t **frame_rate_max**
- struct kmp_media_info_t *kmp*
    - uint32_t **media_type**
    - uint32_t **codec_id**
    - uint32_t **timescale**
    - uint32_t **bitrate**
    - union kmp_media_info_union_t *u*
        - struct kmp_video_media_info_t *video*
            - uint16_t **width**
            - uint16_t **height**
            - struct kmp_rational_t *frame_rate*
                - uint32_t **num**
                - uint32_t **denom**
            - uint32_t **cea_captions**
        - struct kmp_audio_media_info_t *audio*
            - uint16_t **channels**
            - uint16_t **bits_per_sample**
            - uint32_t **sample_rate**
            - uint64_t **channel_layout**

### Block Data
- u_char **extra_data**[*max*]

## Media Info Source Block (`msrc`)
Parent: [*Track Block*](#track-block-trak-3)

### Block Data
- uint32_t **source_id**

## Segment Info Block (`sgnf`)
Parent: [*Track Block*](#track-block-trak-3)

### Block Data
- struct ngx_ksmp_segment_info_elt_t *info*[*max*]
    - uint32_t **index**
    - uint32_t **bitrate**

## Syncer Track Block (`synt`)
Parent: [*Track Block*](#track-block-trak-3)

### Block Data
- struct ngx_live_syncer_persist_track_t *p*
    - int64_t **correction**

## Segment List Block (`slst`)
Parent: [*Channel Block*](#channel-block-chnl-3)

Children: [*Segment List Period Block*](#segment-list-period-block-slpd)

## Segment List Period Block (`slpd`)
Parent: [*Segment List Block*](#segment-list-block-slst)

### Block Header
- struct ngx_live_segment_list_period_t *p*
    - int64_t **time**
    - uint32_t **segment_index**
    - uint32_t **padding**

### Block Data
- struct ngx_ksmp_segment_repeat_t *sr*[*max*]
    - uint32_t **count**
    - uint32_t **duration**

## Timeline Block (`tmln`)
Parent: [*Channel Block*](#channel-block-chnl-3)

Children: [*Timeline Periods Block*](#timeline-periods-block-tlpd)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_live_timeline_persist_t *p*
    - int64_t **last_time**
    - int64_t **last_segment_created**
- struct ngx_live_timeline_persist_manifest_t *mp*
    - int64_t **availability_start_time**
    - uint32_t **first_period_index**
    - uint32_t **first_period_segment_index**
    - int64_t **first_period_initial_time**
    - uint32_t **first_period_initial_segment_index**
    - uint32_t **sequence**
    - int64_t **last_modified**
    - uint32_t **target_duration**
    - uint32_t **target_duration_segments**
    - uint32_t **last_durations**[*3*]
    - uint32_t **reserved**

## Timeline Periods Block (`tlpd`)
Parent: [*Timeline Block*](#timeline-block-tmln-3)

### Block Header
- struct ngx_live_timeline_persist_periods_t *p*
    - uint32_t **merge**
    - uint32_t **reserved**
    - int64_t **first_period_initial_time**

### Block Data
- struct ngx_live_timeline_persist_period_t *pp*[*max*]
    - uint32_t **segment_index**
    - uint32_t **segment_count**
    - int64_t **correction**

## Syncer Block (`sync`)
Parent: [*Channel Block*](#channel-block-chnl-3)

### Block Data
- struct ngx_live_syncer_persist_channel_t *p*
    - int64_t **correction**

## Timeline Channel Block (`tlch`)
Parent: [*Channel Block*](#channel-block-chnl-3)

### Block Data
- struct ngx_live_timeline_persist_channel_t *p*
    - int64_t **last_segment_middle**
    - uint32_t **truncate**
    - uint32_t **reserved**

## Variant Block (`vrnt`)
Parent: [*Channel Block*](#channel-block-chnl-3)

### Block Header
- struct ngx_str_t *id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_live_persist_index_variant_t *p*
    - uint32_t **initial_segment_index**

# Media File (`sgts`)
## Main Block (`klpf`)
Children: [*Segment Block*](#segment-block-sgmt-2), [*Segment Table Block*](#segment-table-block-sntl)

### Block Header
- uint32_t **uncomp_size**
- uint32_t **version**
- uint32_t **type**
- uint64_t **created**

## Segment Block (`sgmt`)
Parent: [*Main Block*](#main-block-klpf-4)

Children: [*Segment Media Info Block*](#segment-media-info-block-sgmi-1), [*Media Info Block*](#media-info-block-minf-3), [*Frame List Block*](#frame-list-block-trun-2), [*Frame Data Block*](#frame-data-block-mdat-2)

### Block Header
- struct ngx_ksmp_segment_header_t *header*
    - uint32_t **track_id**
    - uint32_t **index**
    - uint32_t **frame_count**
    - uint32_t **part_sequence**
    - int64_t **start_dts**

## Segment Media Info Block (`sgmi`)
Parent: [*Segment Block*](#segment-block-sgmt-2)

### Block Header
- struct kmp_media_info_t *kmp*
    - uint32_t **media_type**
    - uint32_t **codec_id**
    - uint32_t **timescale**
    - uint32_t **bitrate**
    - union kmp_media_info_union_t *u*
        - struct kmp_video_media_info_t *video*
            - uint16_t **width**
            - uint16_t **height**
            - struct kmp_rational_t *frame_rate*
                - uint32_t **num**
                - uint32_t **denom**
            - uint32_t **cea_captions**
        - struct kmp_audio_media_info_t *audio*
            - uint16_t **channels**
            - uint16_t **bits_per_sample**
            - uint32_t **sample_rate**
            - uint64_t **channel_layout**

### Block Data
- u_char **extra_data**[*max*]

## Media Info Block (`minf`)
Parent: [*Segment Block*](#segment-block-sgmt-2)

## Frame List Block (`trun`)
Parent: [*Segment Block*](#segment-block-sgmt-2)

### Block Data
- struct ngx_ksmp_frame_t *frame*[*max*]
    - uint32_t **size**
    - uint32_t **key_frame**
    - uint32_t **duration**
    - uint32_t **pts_delay**

## Frame Data Block (`mdat`)
Parent: [*Segment Block*](#segment-block-sgmt-2)

### Block Data
- u_char **data**[*max*]

## Segment Table Block (`sntl`)
Parent: [*Main Block*](#main-block-klpf-4)

Children: [*Segment Table Entry Block*](#segment-table-entry-block-sntr)

### Block Header
- struct ngx_str_t *channel_id*
    - uint32_t **len**
    - u_char **data**[*len*]
- struct ngx_str_t *opaquep*
    - uint32_t **len**
    - u_char **data**[*len*]
- uint64_t **uid**

## Segment Table Entry Block (`sntr`)
Parent: [*Segment Table Block*](#segment-table-block-sntl)

### Block Header
- struct ngx_live_persist_media_entry_t *entry*
    - uint32_t **track_id**
    - uint32_t **segment_index**
    - uint32_t **size**

